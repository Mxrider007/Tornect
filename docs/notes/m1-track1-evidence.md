# M1 track 1 evidence — `tornect host` / `tornect ping` over the live Tor network

Machine: `mx-vm` (Ubuntu 26.04, 4 vCPU, 7 GiB, VMware NAT, Rust 1.96), 2026-08-28.
Debug build (`opt-level = 1`, dependencies `opt-level = 3`), `tor-pow` feature on
(default). All timestamps UTC. Raw logs were written to
`target/tornect-test/{host,host2,ping,ping2}.log` (git-ignored); the excerpts below are
trimmed to the relevant lines: `DEBUG` lines and Arti's repeated status lines
(`onion service status state=Shutdown/Bootstrapping … problem="introduction point
errors (0)"`, `Too many preemptive onion service circuits failed`) are left out, the
one `DEBUG` crypto-provider line that dates the start of run 1 is kept, and no line
was edited. The tokio teardown panic that runs 1–2 printed at exit (fixed in run 7,
see "Runs 3–8") is kept in place in both host excerpts.

## What was demonstrated

1. Host instance `h1` (`TORNECT_HOME=target/tornect-test/h1`, fresh) publishes an onion
   service for its persisted identity; the ID is printed before bootstrap completes.
2. Client instance `h2` (separate `TORNECT_HOME`, fresh) bootstraps, connects by ID
   only, exchanges 5 ping/pong round trips.
3. Host is killed with SIGINT (Ctrl-C path) and restarted on the same state directory:
   it prints the **same** Tornect ID, becomes reachable again, and answers 5 more pings.
4. `tornect id` on `h1` prints the same ID (`created: false`).

Tornect ID under test: `5fgkeslwnfhhhlb24c7ghn5u3rigo3vlyhm6weqbd23qtr44chvoxzad.onion`
(Arti nickname `tornect-5fgkeslw`).

## Timeline

| UTC | Event | Source |
|---|---|---|
| 21:04:10 | `TORNECT_HOME=…/h1 timeout 480 cargo run -q -p tornect -- host` started | `demo-timeline.log` |
| 21:04:22.979 | rustls `ring` provider installed; new Tornect ID generated (`h1/state/keys`) | `host.log` |
| 21:04:22.983 | Tor client created (`h1/state/arti`), bootstrap started in background | `host.log` |
| 21:04:22.983 | host identity installed into Arti keystore (`nickname=tornect-5fgkeslw`) | `host.log` |
| 21:04:22.985 | onion service launched; **`Tornect ID: 5fgkeslw…xzad.onion`** printed — **2 ms after client creation, 12 s before bootstrap finished** | `host.log` |
| 21:04:34.944 | `Tor bootstrap complete` (cold: **12.0 s**; consensus + microdescs downloaded) | `host.log` |
| 21:05:36.271 | onion service `state=Running reachable=true` → **`REACHABLE`** (61 s after bootstrap, 73 s after launch) | `host.log` |
| 21:05:54 | `TORNECT_HOME=…/h2 cargo run -q -p tornect -- ping <id> --count 5` started (fresh instance) | `demo-timeline.log` |
| 21:06:03.318 | client `Tor bootstrap complete` (cold: **8.7 s**) | `ping.log` |
| 21:06:12.332 | `onion stream open` — rendezvous **9.0 s** | `ping.log` |
| 21:06:13–16 | 5 pings answered; **`PING OK n=5 min/avg/max=737.2/813.3/972.4 ms`**; exit 0 | `ping.log`, `host.log` |
| 21:07:35 | `pkill -INT tornect` → `Ctrl-C: shutting down`, `onion service stopped`, exit status 0 | `host.log`, `demo-timeline.log` |
| 21:08:03 | host run 2 started on the **same** `h1` | `demo-timeline.log` |
| 21:08:03.383 | onion service launched; **`Tornect ID: 5fgkeslw…xzad.onion`** printed again (**identical**) | `host2.log` |
| 21:08:04.479 | `Tor bootstrap complete` (warm: **1.1 s**) | `host2.log` |
| 21:09:10.977 | `state=Running` → **`REACHABLE`** (67 s after launch) | `host2.log` |
| 21:09:26 | ping run 2 from `h2` (warm) | `demo-timeline.log` |
| 21:09:28.989 | client bootstrap complete (warm: **1.7 s**) | `ping2.log` |
| 21:09:36.709 | stream open — rendezvous **7.7 s** | `ping2.log` |
| 21:09:37–39 | **`PING OK n=5 min/avg/max=540.6/586.1/656.5 ms`**; exit 0 | `ping2.log`, `host2.log` |
| 21:09:50 | SIGINT → clean exit status 0 | `demo-timeline.log` |

## Log excerpts

`host.log` (run 1, cold):

```
2026-08-28T21:04:22.979139Z DEBUG tornect_signal::tor::crypto_provider: installed rustls `ring` crypto provider
generated a new Tornect ID (stored in /home/mx/Tornect/target/tornect-test/h1/state/keys)
bootstrapping Tor (~30 s cold, a few seconds with a warm cache)...
2026-08-28T21:04:22.983226Z  INFO tornect_signal::tor::node: Tor client created state_dir=/home/mx/Tornect/target/tornect-test/h1/state/arti
publishing onion service (PoW defense on; reachable after descriptor upload, typically ~10 s past bootstrap, up to 2 min on a cold start)...
2026-08-28T21:04:22.983398Z  INFO tornect_signal::tor::identity: installing host identity into Arti keystore nickname=tornect-5fgkeslw
2026-08-28T21:04:22.985133Z  INFO tornect_signal::tor::node: onion service launched address=5fgkeslwnfhhhlb24c7ghn5u3rigo3vlyhm6weqbd23qtr44chvoxzad.onion nickname=tornect-5fgkeslw
Tornect ID: 5fgkeslwnfhhhlb24c7ghn5u3rigo3vlyhm6weqbd23qtr44chvoxzad.onion
tor: bootstrap   0%
tor: bootstrap   8%
tor: bootstrap  15%
tor: bootstrap  36%
tor: bootstrap  45%
tor: bootstrap 100%
2026-08-28T21:04:34.943896Z  INFO tornect_signal::tor::node: Tor bootstrap complete
tor: ready
onion service: Bootstrapping
2026-08-28T21:05:36.270974Z  INFO tornect_signal::tor::listener: onion service status state=Running reachable=true problem="-"
REACHABLE
onion service reachable (Running); waiting for pings
client connected over Tor
answered ping #1
answered ping #2
answered ping #3
answered ping #4
answered ping #5
ping session ended: I/O error: Stream not connected
Ctrl-C: shutting down
2026-08-28T21:07:35.440636Z  INFO tornect_signal::tor::listener: onion service stopped address=5fgkeslwnfhhhlb24c7ghn5u3rigo3vlyhm6weqbd23qtr44chvoxzad.onion
2026-08-28T21:07:35.440858Z  INFO tornect_signal::tor::node: Tor node shutting down

thread 'tokio-rt-worker' (159607) panicked at /home/mx/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.53.1/src/runtime/time/entry.rs:539:9:
A Tokio 1.x context was found, but it is being shutdown.
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```

`ping.log` (run 1, fresh `h2`):

```
bootstrapping Tor (~30 s cold, a few seconds with a warm cache)...
2026-08-28T21:05:54.613516Z  INFO tornect_signal::tor::node: Tor client created state_dir=/home/mx/Tornect/target/tornect-test/h2/state/arti
tor: bootstrap   0%
tor: bootstrap   8%
tor: bootstrap  15%
tor: bootstrap  36%
tor: bootstrap  45%
tor: bootstrap 100%
2026-08-28T21:06:03.318203Z  INFO tornect_signal::tor::node: Tor bootstrap complete
connecting to 5fgkeslwnfhhhlb24c7ghn5u3rigo3vlyhm6weqbd23qtr44chvoxzad.onion (rendezvous usually takes 5-30 s, up to 60 s)...
2026-08-28T21:06:12.332072Z  INFO tornect_signal::tor::node: onion stream open host=5fgkeslwnfhhhlb24c7ghn5u3rigo3vlyhm6weqbd23qtr44chvoxzad.onion
connected in 9.0 s
ping 1/5: rtt 804.2 ms
ping 2/5: rtt 771.3 ms
ping 3/5: rtt 972.4 ms
ping 4/5: rtt 737.2 ms
ping 5/5: rtt 781.6 ms
PING OK n=5 min/avg/max=737.2/813.3/972.4 ms
2026-08-28T21:06:16.399099Z  INFO tornect_signal::tor::node: Tor node shutting down
```

`host2.log` (run 2 after SIGINT, same `h1`, warm):

```
bootstrapping Tor (~30 s cold, a few seconds with a warm cache)...
2026-08-28T21:08:03.380027Z  INFO tornect_signal::tor::node: Tor client created state_dir=/home/mx/Tornect/target/tornect-test/h1/state/arti
publishing onion service (PoW defense on; ...)...
2026-08-28T21:08:03.382835Z  INFO tornect_signal::tor::node: onion service launched address=5fgkeslwnfhhhlb24c7ghn5u3rigo3vlyhm6weqbd23qtr44chvoxzad.onion nickname=tornect-5fgkeslw
Tornect ID: 5fgkeslwnfhhhlb24c7ghn5u3rigo3vlyhm6weqbd23qtr44chvoxzad.onion
tor: bootstrap   0%
tor: bootstrap  30%
tor: bootstrap  85%
2026-08-28T21:08:04.479399Z  INFO tornect_signal::tor::node: Tor bootstrap complete
tor: bootstrap 100%
tor: ready
onion service: Bootstrapping
2026-08-28T21:09:10.977186Z  INFO tornect_signal::tor::listener: onion service status state=Running reachable=true problem="-"
REACHABLE
onion service reachable (Running); waiting for pings
client connected over Tor
answered ping #1
answered ping #2
answered ping #3
answered ping #4
answered ping #5
ping session ended: I/O error: Stream not connected
Ctrl-C: shutting down
2026-08-28T21:09:50.281651Z  INFO tornect_signal::tor::listener: onion service stopped address=5fgkeslwnfhhhlb24c7ghn5u3rigo3vlyhm6weqbd23qtr44chvoxzad.onion
2026-08-28T21:09:50.281676Z  INFO tornect_signal::tor::node: Tor node shutting down

thread 'tokio-rt-worker' (165020) panicked at /home/mx/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.53.1/src/runtime/time/entry.rs:539:9:
A Tokio 1.x context was found, but it is being shutdown.
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
```

`ping2.log` (run 2, warm `h2`):

```
2026-08-28T21:09:27.292188Z  INFO tornect_signal::tor::node: Tor client created state_dir=/home/mx/Tornect/target/tornect-test/h2/state/arti
2026-08-28T21:09:28.988914Z  INFO tornect_signal::tor::node: Tor bootstrap complete
2026-08-28T21:09:36.708791Z  INFO tornect_signal::tor::node: onion stream open host=5fgkeslwnfhhhlb24c7ghn5u3rigo3vlyhm6weqbd23qtr44chvoxzad.onion
connected in 7.7 s
ping 1/5: rtt 656.5 ms
ping 2/5: rtt 540.6 ms
ping 3/5: rtt 621.5 ms
ping 4/5: rtt 553.1 ms
ping 5/5: rtt 558.9 ms
PING OK n=5 min/avg/max=540.6/586.1/656.5 ms
```

`tornect id --json` on `h1` (between the two host runs):

```
{"created":false,"device_fingerprint":"d2ac-2715-3aa1-a203","device_id":"ysiubomlgrvysvxhdaxtyuttg2ve7wydygjy4lfnnjgunh4vw23a","keystore":"/home/mx/Tornect/target/tornect-test/h1/state/keys","tornect_id":"5fgkeslwnfhhhlb24c7ghn5u3rigo3vlyhm6weqbd23qtr44chvoxzad.onion"}
```

## Persisted layout after the runs (`h1`, 148 KB state, 46 MB cache)

```
h1/state/keys/host-identity.ed25519-seed.secret                       <- Tornect's seed (0600)
h1/state/keys/device-identity.ed25519-seed.secret
h1/state/arti/keystore/hss/tornect-5fgkeslw/ks_hs_id.ed25519_expanded_private   <- installed by tornect-signal (M1-1)
h1/state/arti/keystore/hss/tornect-5fgkeslw/ks_hs_blind_id+2069{2,3}_1440_43200.ed25519_expanded_private
h1/state/arti/keystore/hss/tornect-5fgkeslw/ks_hs_desc_sign+2069{2,3}_1440_43200.ed25519_private
h1/state/arti/keystore/hss/tornect-5fgkeslw/ipts/{k_hss_ntor,k_sid}+<lid>.*_private  (x3 intro points)
h1/state/arti/hss/tornect-5fgkeslw/{ipts.json,iptpub.json,iptreplay/<lid>.bin x3}
h1/state/arti/hss/tornect-5fgkeslw/{pow_manager.json,pow_nonces/*.bin}            <- PoW manager active (tor-pow)
h1/state/arti/state/{guards.json,circuit_timeouts.json,state.lock}
```

The three `iptreplay`/`ipts` records were reused by run 2 (warm restart republished
within ~67 s, matching `docs/research/arti.md` §12's "warm restarts republish quickly").

## `live_tor_roundtrip` (ignored integration test, host + client in one process)

`CARGO_BUILD_JOBS=3 TMPDIR=$PWD/target/tmp cargo test -p tornect-signal --test live -- --ignored --nocapture`,
state under `target/tornect-test/live/{host,client}` (its own identity,
`6blvfapklvbcui4mdci7ciyiqjub6gpmpy5kiu4qa53biu7bzub43cid.onion`, same in all three runs):

| Run (UTC) | State | Outcome |
|---|---|---|
| 21:43:15 | both cold | host launched, client bootstrapped 13.0 s, connected 26.2 s (descriptor found without any retry), pings 566 / 783 / 585 ms — then **failed** at the very end: the client's `shutdown()` raced with the host dropping its side and the test propagated that; it also showed that Arti reports a dropped peer stream as the error "Received an END cell with reason MISC" (the CLI host had been logging that as `ping session ended: I/O error`) |
| 21:46:56 | warm | client bootstrapped 1.4 s, connected 12.5 s, pings 834 / 827 / 852 ms; same end-of-stream failure (`OnionStream` did not yet map `END(MISC)` to EOF); `RUST_BACKTRACE=1` re-run at 21:48 produced the PoW-thread backtrace quoted above |
| 21:54:06 | warm, final code | `OnionStream::poll_read` maps `END(MISC|DONE)` to EOF, test tears its runtime down with `tornect_signal::shutdown_runtime`: bootstrapped 1.5 s, connected 8.0 s, pings 811 / 992 / 907 ms, `host answered 3 ping(s)`, **`test live_tor_roundtrip ... ok` (11.76 s), no stray output** |

## Gate

`CARGO_BUILD_JOBS=3 TMPDIR=$PWD/target/tmp cargo xtask verify` on the track-1 tree
(the code of run 8 and the passing live test), 2026-08-28 21:55–21:57 UTC:

```
==> plan sync (TORNECT_PLAN.md == docs/PLAN.md)          ok
==> cargo fmt --all -- --check                            ok
==> cargo clippy --workspace --all-targets -- -D warnings ok
==> cargo test --workspace                                ok (139.0s)
    tornect-signal: 24 passed; live_tor_roundtrip ignored (needs --ignored)
    tornect-core:   26 passed
==> cargo doc --workspace --no-deps (RUSTDOCFLAGS=-D warnings) ok (3.2s)
verify: all gates green            (VERIFY_EXIT=0 at 21:57:47Z)
```

Same command on the tree with the security-review fixes applied (next section),
2026-08-28 22:37–22:39 UTC (`target/tornect-test/review-fix-verify.log`):

```
==> plan sync (TORNECT_PLAN.md == docs/PLAN.md)          ok
==> cargo fmt --all -- --check                            ok (0.1s)
==> cargo clippy --workspace --all-targets -- -D warnings ok (3.0s)
==> cargo test --workspace                                ok (141.8s)
    tornect-signal: 35 passed; live_tor_roundtrip ignored (needs --ignored)
    tornect-core:   26 passed
==> cargo doc --workspace --no-deps (RUSTDOCFLAGS=-D warnings) ok (5.2s)
verify: all gates green            (VERIFY_EXIT=0 at 22:39:53Z)
```

Earlier gate iterations caught (and the fixes are in the tree): an unread
`OnionListener.service` field (now `_service`, kept for its `Drop`), `eprintln!` in the
live test (allowed there explicitly), an unnecessary `std::future::Future`
qualification, a mock stream in a `ping` test that ignored `ReadBuf` capacity, and a
rustdoc link to a private item.

## Unit tests and build checks

- `cargo test -p tornect-signal`: 35 unit tests pass after the security-review fixes
  (framing 7 incl. proptest, ping 7, crypto provider 1, config 3, identity 8, node 2,
  listener 7; the track-1 tree before the review had 24: ping 5, config 2, identity 5,
  listener 2); `tests/live.rs::live_tor_roundtrip` is `#[ignore]` (run with
  `cargo test -p tornect-signal --test live -- --ignored --nocapture`).
  `tor::identity::tests::arti_derives_the_same_onion_address_as_tornect_core` asserts
  `onion_address_for(&identity) == identity.id()` for 32 random seeds plus a fixed
  vector; `install_is_idempotent_and_arti_reads_back_the_same_address` installs the
  key through `tor-keymgr` and reads it back through `HsIdPublicKeySpecifier` exactly
  as Arti's launch path does.
- `cargo tree -i aws-lc-sys -p tornect-signal` → `did not match any packages`;
  `cargo tree -i openssl-sys --workspace` → `did not match any packages`.
  Resolved: `ring 0.17.14`, `rustls 0.23.43`, `arti-client 0.45.0`, `tor-hsservice 0.45.0`,
  `equix 0.7.1`, `hashx 0.9.1`, `dynasmrt 5.1.0`, `tokio 1.53.1`.
- First build of the Arti graph: ~3.5 min with `CARGO_BUILD_JOBS=3`; incremental
  rebuild of `tornect` ~2 min.

## Runs 3–8: `--once`, teardown and the polish that followed

Runs 1–2 exposed three rough edges (all visible in the excerpts above): a tokio panic
printed during process teardown, `Stream not connected` when the client dropped its
stream without a graceful close, and `Problem::Ipt([])` shown as "introduction point
errors (0)". They were fixed and re-verified on the live network with `tornect host
--once` (exit after the first answered ping), same `h1`/`h2` directories:

| Run (UTC) | Binary | Result |
|---|---|---|
| host 3 21:23:29 / ping 3 21:23:57 | graceful stream close + peer-gone handling; `Runtime::shutdown_timeout` | same ID; `REACHABLE` 10 s after launch (IPT/descriptor state reused); ping: connect 8.1 s, rtt 600.9 / 590.0 ms, then the host exited after ping #1 (`--once`) and the third ping failed non-zero as it should. Host exit 0 — **but the tokio panic was still printed** |
| host 4 21:28:06 / ping 4 21:28:35 | runtime leaked (`mem::forget`) instead of torn down | no panic; ping: connect 6.6 s, 857.2 ms, then `The host closed the connection mid-session (...)` (exit 1, correct for `--once`) — **but no "Flushed persistent state at exit"**: `guards.json` last written at start-up |
| host 5 21:30:52 / ping 5 21:32:21 | wait for the `TorClient` `Arc` to be released (0 ms) + 1.5 s settle, runtime still leaked | `PING OK n=1 … 784.2 ms`; no panic; still no exit flush; Arti's periodic flush observed at 21:31:52 (60 s cadence, `tor-circmgr` `update_persistent_state`) |
| host 6 21:34:13 / ping 6 21:34:38, 6b 21:37:02 | 10 s settle with `tor_circmgr=debug` | **Tor transient**: ping 6 timed out after 60 s — host logged `rendezvous failed error=Could not connect rendezvous circuit.`, `Too many preemptive onion service circuits failed`, `Could not connect to guard`; the client printed `Tor did not answer in time. Check the network on both ends and retry.` (exit 1). Retry 6b: connect 6.9 s, `PING OK … 816.2 ms`. Still no exit flush after 10 s → root cause found: Arti's directory manager task holds the circuit manager, so `CircMgr::drop` (which flushes) only runs when the **runtime** is torn down |
| host 7 21:39:25 / ping 7 21:39:56 | `TorNode::shutdown()` (drop client, wait for release, 250 ms settle) then `Runtime::shutdown_timeout(5 s)` with tokio's PoW-thread panic message muted during teardown | same ID; `REACHABLE` at 21:39:39; ping: connect 8.0 s, `PING OK n=1 … 919.6 ms`; host `Flushed persistent state at exit.` 254 ms after shutdown began, client 265 ms; `guards.json` rewritten at exit in both homes; **0 panic lines**; both exit 0 |
| host 8 22:00:15 / ping 8 22:00:51 | **final tree** (teardown moved into `tornect_signal::shutdown_runtime`, `OnionStream` maps Arti's `END(MISC)` to EOF), host without `--once` | same ID; `REACHABLE` at 22:00:27; ping: connect 9.6 s, **`PING OK n=3 min/avg/max=591.6/609.7/633.8 ms`**; host logs `answered ping #1..#3` then **`client disconnected after 3 ping(s)`** (clean EOF instead of the earlier I/O error); `Ctrl-C` → `onion service stopped` → `Flushed persistent state at exit.` 255 ms later; both exit 0; **0 panic lines** |

`host7.log` / `ping7.log` teardown (verbatim):

```
2026-08-28T21:40:06.416682Z  INFO tornect_signal::tor::node: Tor node shutting down
2026-08-28T21:40:06.416713Z  INFO tor_hsservice::ipt_mgr: HS service tornect-5fgkeslw: terminating due to shutdown signal
2026-08-28T21:40:06.667435Z DEBUG tornect_signal::tor::node: Tor client released released=true released_after_ms=0
2026-08-28T21:40:06.670218Z  INFO tor_circmgr: Flushed persistent state at exit.

2026-08-28T21:40:06.853876Z  INFO tornect_signal::tor::node: Tor node shutting down
2026-08-28T21:40:07.106032Z DEBUG tornect_signal::tor::node: Tor client released released=true released_after_ms=0
2026-08-28T21:40:07.119428Z  INFO tor_circmgr: Flushed persistent state at exit.
```

What the teardown investigation established (all from the extracted sources, see the
code comments in `apps/tornect/src/tor_cmd.rs::block_on` and `TorNode::shutdown`):

- The panic `A Tokio 1.x context was found, but it is being shutdown` comes from
  Arti's proof-of-work manager (`tor-hsservice-0.45.0/src/pow/v1.rs` lines 1105 and
  1236, feature `hs-pow-full`): two `spawn_blocking` loops that re-enter
  `block_on(receiver.next())` / `block_on(runtime.sleep(wait_time))` and have no exit
  path. tokio shuts its time driver down before waiting for blocking threads, so the
  sleeping thread's next poll trips `TimerEntry::poll_elapsed`'s assertion
  (`tokio-1.53.1/src/runtime/time/entry.rs:539`); `RUST_BACKTRACE=1` from the live
  test shows exactly `RendRequestReceiver::expire_old_requests_loop` (v1.rs:1236) ←
  `start_accept_thread` (v1.rs:955) ← `tokio::runtime::blocking::pool`. The threads
  start for every launched onion service whenever the feature is compiled in, even
  with `enable_pow = false`. The unwind is caught by tokio's blocking pool; only the
  message is a problem. It cannot happen in the client role (no onion service) and is
  muted, for exactly that message, only while `tornect_signal::shutdown_runtime`
  tears the runtime down (used by the CLI and the live test). Worth reporting upstream.
- Arti has no way to close a client `DataStream` with `END(DONE)`: `shutdown()`
  flushes and then closes our send side (`tor-proto-0.45.0/src/client/stream/data.rs`
  `poll_close` → `poll_flush_impl(cx, true)` → `StreamTarget::close`), after which
  the reactor ends the stream with its default
  `CloseStreamBehavior::SendEnd(End::new_misc())` (`src/stream.rs` 80–83); dropping
  the stream ends the same way. Either way the peer's reader surfaces the I/O error
  "Received an END cell with reason MISC". `OnionStream::poll_read` therefore maps
  `END(MISC)` (and `DONE`) to a clean EOF — it *is* Arti's "peer hung up" — so every
  protocol on top sees `Ok(0)` / `read_frame → Ok(None)`.
- `tor-circmgr` flushes guard/circuit state every 60 s (`update_persistent_state`,
  `fire_in(Duration::from_secs(60))`) and once more from `CircMgrInner::drop`; the
  latter requires the runtime teardown because `tor-dirmgr`'s background task keeps a
  strong reference to the circuit manager. Leaking the runtime would lose at most the
  last minute of guard-state changes.

## Security-review fixes (2026-08-28, 22:00–23:00 UTC)

The M1 track-1 security review found one high, three medium and ten low issues;
all were applied (decisions M1-2 amended, M1-4/M1-5/M1-6 added). What changed:

| Finding | Fix | Proof |
|---|---|---|
| 8-slot rendezvous semaphore held for the circuit lifetime = 8-connection lockout (high) + permits counted idle circuits (medium) | `tor::listener`: permit held only across `RendRequest::accept` (60 s cap); 64 live circuits; a circuit with no open signaling stream for 30 s is dropped (closes it); accepted `OnionStream`s carry a guard that pauses the idle clock; `ping::serve` cuts a peer silent for 30 s | unit tests `silent_circuit_is_dropped_after_the_idle_deadline`, `open_stream_pauses_the_idle_deadline_until_it_closes`, `ping::silent_client_is_disconnected_after_the_deadline`, `deadline_is_per_frame_not_per_session` (scripted duplex streams) |
| `tor.restricted_discovery = true` silently ignored (medium) | `onion_service_config` refuses with `SignalError::Config`; same for `pow_defense` on a build without `tor-pow` (`--no-pow` is the override) | `restricted_discovery_is_refused_until_implemented`, `onion_service_config_builds_with_and_without_pow` |
| Rotate ID left Arti's expanded key + service state on disk (medium) | `tornect_signal::forget_identity` (keymgr `list_matching` + `remove_entry`, directory removal, `tor-persist` `purge_instances`); `tornect rotate-id` calls it before writing the new seed; keystore mismatch under a nickname is refused instead of overwritten | `forget_identity_removes_its_keys_and_service_state_only`, `forget_identity_refuses_while_the_service_is_running`, `a_foreign_key_under_the_nickname_is_refused_not_overwritten`; CLI demo below |
| Unknown-port `BEGIN` kept the circuit alive (low) | `StreamRequest::shutdown_circuit()` — tor-hsrproxy's default (`proxy.rs` 225–250); the per-circuit loop ends | `foreign_request_ends_the_circuit_immediately` |
| Per-circuit tasks detached, survived listener drop (low) | circuit tasks live in the accept loop's `JoinSet`; `OnionListener::drop` aborts the accept task, which aborts them | `aborting_the_accept_loop_aborts_every_circuit_task` |
| Unzeroized SHA-512 stack copy (low) | `Sha512::new().chain_update(seed).finalize_into(&mut *expanded)`; the by-value copy Arti's `from_secret_key_bytes` takes is documented as an API limitation | `expand_seed_matches_rfc8032_clamping` unchanged (same output) |
| Panic-hook swap not re-entrant, muted at `debug` (low) | `static Mutex` serializes `shutdown_runtime`; muted panic logged at `warn` | — (behaviour unchanged for the CLI) |
| No fuzz target, cargo-deny not run, unused `tor-config` dep (low) | `fuzz/fuzz_targets/framing.rs` (+ `exclude = ["fuzz"]`), cargo-deny 0.20.2 run from a prebuilt binary, `tor-config` removed from both manifests and `docs/DEPENDENCIES.md` | fuzz and deny results below |
| Comments claiming `END(DONE)` on `shutdown()` (low); excerpt header / stale test counts (low) | comments in `tor_cmd.rs`, `tests/live.rs` and the paragraph above reworded to the verified mechanism (`poll_close` → `StreamTarget::close` → reactor default `END(MISC)`); excerpts now carry the panic lines; inventory says 35 | this file |

`tornect rotate-id --yes` on a copy of the `h1` state (`target/tornect-test/h1-rotate`,
binary from the fixed tree, 22:37 UTC; `find` output filtered to the two Arti
directories):

```
--- before
state/arti/hss/tornect-5fgkeslw/{iptpub.json,ipts.json,iptreplay/,pow_manager.json,pow_nonces/}
state/arti/hss/tornect-5fgkeslw.lock
state/arti/keystore/hss/tornect-5fgkeslw/   (ks_hs_id, 2× ks_hs_blind_id, 2× ks_hs_desc_sign, ipts/{k_hss_ntor,k_sid}×3)
--- rotate
2026-08-28T22:37:50.999300Z  INFO tornect_signal::tor::identity: removed identity from Arti's keystore and state nickname=tornect-5fgkeslw keys_removed=11 unrecognized_files_removed=0 state_removed=true
removed the old ID's Tor keys and service state (11 key(s), intro-point state)
New Tornect ID: rwat3m6qpk2n3nzu7rcspzc42ft3ktyeffgxl3qy45gigvvrce4vayad.onion
exit=0
--- after
state/arti/hss            (empty)
state/arti/keystore/hss   (empty)
--- id after
{"created":false,...,"tornect_id":"rwat3m6qpk2n3nzu7rcspzc42ft3ktyeffgxl3qy45gigvvrce4vayad.onion"}
--- sessions.log
{"ts":"2026-08-28T22:37:51.000709577Z","event":"host_id_rotated","unattended":false}
```

`cargo deny check` (cargo-deny 0.20.2, `target/tornect-test/cargo-deny.log`):
`advisories ok, bans ok, licenses ok, sources ok`, 36 `duplicate` warnings
(`multiple-versions = "warn"`), 6 unused license allowances. The first run failed
`bans` because every version-less `path` dependency between the workspace's own
crates was reported as a wildcard; `bans.allow-wildcard-paths = true` fixes that.

Fuzzing (`target/tornect-test/fuzz-framing.log`; nightly `rustc 1.100.0-nightly
(e457a7b0d 2026-08-27)` installed with `rustup toolchain install nightly --profile
minimal`, cargo-fuzz 0.13.2, corpus kept under `target/fuzz-corpus/framing` so no
generated inputs land in git):

```
cargo +nightly fuzz build framing            build start 22:40:38Z, build done 22:45:57Z (ASan + sancov, 3 jobs)
cargo +nightly fuzz run framing target/fuzz-corpus/framing -- -max_total_time=600 -max_len=70000
#1503     NEW    cov: 222 ft: 231 corp: 6/32b lim: 14 ...      <- coverage plateau after 1.5k inputs
#82388245 DONE   cov: 222 ft: 231 corp: 6/26b lim: 70000 exec/s: 137085 rss: 417Mb
Done 82388245 runs in 601 second(s)
FUZZ_EXIT=0                                  end 22:56:00Z; fuzz/artifacts/framing/ empty (no crash)
```

## Second security-review round (2026-08-28, 23:00–23:35 UTC)

The review of the tree above found one high, three medium and six low issues; all
were applied (decisions M1-4 and M1-6 amended). What changed:

| Finding | Fix | Proof |
|---|---|---|
| Host pong write unbounded: a peer withholding Tor flow-control credit pins the task, its `StreamGuard` and the circuit's `MAX_LIVE_CIRCUITS` permit forever (high) | `ping::serve` puts the pong write under the same per-frame deadline as the read (`Timeout("sending the pong")`); host-side `OnionStream` gets a `StallTimer`: a `poll_write`/`poll_flush`/`poll_shutdown` that makes no progress for `STREAM_WRITE_TIMEOUT` (30 s) fails with `TimedOut`, so every future protocol inherits the bound; `StreamRequest::accept` capped at `ACCEPT_TIMEOUT` (10 s) | `ping::stalled_pong_write_is_cut_after_the_deadline` (scripted `AsyncWrite` whose `poll_write`/`poll_flush` stay `Pending`), `listener::stall_timer_fails_a_write_with_no_progress_and_resets_on_progress`; live roundtrip below (host writes now go through the wrapper) |
| Chatty unauthenticated peer holds all 64 slots indefinitely; M1-4 covered silent peers only (medium) | `ping::serve` ends a session after `SESSION_TIMEOUT` (120 s) or `MAX_PINGS_PER_SESSION` (100, `SignalError::BudgetExhausted`); `tornect host` serves at most `MAX_PING_SESSIONS` = 64 sessions at once (semaphore, extra streams closed at once); `tornect ping --count` capped at 100; M1-4 and the listener module docs state the residual exposure (no per-peer accounting before the envelope's signed HELLO) | `chatty_client_is_cut_when_the_session_budget_is_spent`, `ping_budget_ends_the_session`; `tornect ping … --count 101` → `error: invalid value '101' for '--count <COUNT>': 101 is not in 1..=100` (exit 2) |
| `forget_identity` deleted Arti's keys before the running-service lock check (medium, reported twice) | `StateDirectory::acquire_instance` first — the very lock a running host holds — refusing with "in use" before anything is removed; keys, keystore directory and then `InstanceStateHandle::purge` all happen under that lock (`PurgeOne` handler gone) | `forget_identity_refuses_while_the_service_is_running` now asserts the key file, its keystore entry, `ipts.json` and the lock file survive the refusal, and that the retry removes exactly `keys_removed: 1`, state and lock |
| 64 KiB allocated per announced header; ping accepted any size; 16 streams per circuit (low) | `framing::read_frame_max(reader, max_len)` (`FrameError::TooLarge { len, max }`), `ping::serve` passes `MSG_LEN` = 22; `MAX_STREAMS_PER_CIRCUIT` 16 → 4 | `framing::protocol_cap_rejects_the_header_without_touching_the_body`, `ping::host_rejects_garbage` (65536-byte header → `TooLarge { len: 65536, max: 22 }`); fuzz target updated for the struct variant (nightly type-check below) |
| PoW rendezvous queue at Arti's default 8192 ≈ 32 MB (low) | `POW_REND_QUEUE_DEPTH` = 1024, set beside the other bounds | `onion_service_config_builds_with_and_without_pow` reads `pow_rend_queue_depth`, `max_concurrent_streams_per_circuit` and `num_intro_points` back from the built config |
| Overload fingerprint: `CONNECTED` then `END(MISC)` instead of `END(DONE)` (low) | `handle_stream_request` checks `incoming.is_closed() \|\| incoming.capacity() == 0` before accepting and answers `StreamRequest::reject(End::new_with_reason(EndReason::DONE))`, keeping the circuit; `try_send` still covers the race | — (needs Arti's reactor; the branch is a straight-line call into the verified `reject`) |
| Foreign rustls provider logged at `debug`; unzeroized by-value key copies (low) | already-installed case logged at `warn` with the provider in force (`key_provider` `Debug`: `Ring`/`AwsLcRs`); `cargo xtask verify` gains a `forbidden dependencies` gate (`cargo tree --workspace -i` for `aws-lc-rs`, `aws-lc-sys`, `openssl-sys` must report `did not match any packages`); the by-value copies are documented in `keys.rs`/`identity.rs` as accepted | `install_is_idempotent_and_ring_is_the_provider_in_force` asserts `Ring`; gate output below |
| Excerpt header over-claims "verbatim minus DEBUG"; stale "END with reason DONE" sentence (low) | header now says which lines are left out; the gotcha bullet says `END(MISC)` → EOF | this file |

Gates on the fixed tree (`target/tornect-test/review2-gates.log`, `review2-verify.log`):

```
2026-08-28T23:26:25Z  cargo xtask verify
==> plan sync (TORNECT_PLAN.md == docs/PLAN.md)
Error: TORNECT_PLAN.md and docs/PLAN.md differ; copy the edited one over the other
VERIFY_EXIT=1
```

The plan-sync gate is red for a reason outside this change set: `TORNECT_PLAN.md` was
being rewritten by the envelope track while these fixes were verified (its mtime moved
at 23:26:19, 23:27:08 and 23:31:23 UTC; 460 lines differ from `docs/PLAN.md`, in both
directions; same result on a re-run at 23:34 UTC, `review2-verify-final.log`), so
neither copy was copied over the other here — that sync is one `cp` for whoever owns
the edit, after which `verify` runs through. The four code gates were run
individually, exactly as `verify` runs them:

```
2026-08-28T23:27:14Z
==> forbidden dependencies absent (aws-lc-rs, aws-lc-sys, openssl-sys)   ok   (each: `did not match any packages`)
==> cargo fmt --all -- --check                                            ok (0.1s)
==> cargo clippy --workspace --all-targets -- -D warnings                 ok (23.6s)
cargo test --workspace: tornect_core 26 passed; tornect_signal 40 passed; live_tor_roundtrip ignored; TEST_PIPE_EXIT=0
cargo doc --workspace --no-deps (RUSTDOCFLAGS=-D warnings): Generated target/doc/tornect/index.html; DOC_EXIT=0
2026-08-28T23:29:52Z
```

`tornect-signal` is at 40 unit tests: framing 8 (incl. proptest), ping 10, crypto
provider 1, config 3, identity 8, node 2, listener 8.

Live roundtrip on the fixed tree (`target/tornect-test/review2-live.log`, warm
`target/tornect-test/live/{host,client}`; the host's pongs now pass through the
`StallTimer`-wrapped `OnionStream` and the capacity-checked accept path):

```
2026-08-28T23:30:22Z
[  0.0s] host launched 6blvfapklvbcui4mdci7ciyiqjub6gpmpy5kiu4qa53biu7bzub43cid.onion
[  2.4s] client bootstrapped
[ 21.6s] client connected
[ 22.2s] ping 1 rtt 586 ms
[ 22.8s] ping 2 rtt 563 ms
[ 23.4s] ping 3 rtt 665 ms
[ 23.7s] host answered 3 ping(s)
test live_tor_roundtrip ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 24.22s
LIVE_EXIT=0
```

Same ID as the three earlier live runs. The fuzz target (updated for
`FrameError::TooLarge { len, max }`) type-checks on nightly:
`cargo +nightly check` in `fuzz/` → `Checking tornect-fuzz v0.0.0`, exit 0, 23:30–23:32
UTC (`target/tornect-test/review2-fuzz-check.log`); the 10-minute run was not repeated
(the parser's accept path is unchanged, only the error variant's shape).

## Third security-review round (2026-08-29, 00:00–00:25 UTC)

The review of the tree above found one high, one medium (reported twice) and six
low issues; all were applied (decisions M1-2 and M1-4 amended). What changed:

| Finding | Fix | Proof |
|---|---|---|
| The accept loop polled Arti's `RendRequest` stream unconditionally and dropped the overflow itself, so Arti's PoW queue — the only place it measures load and orders by effort — was always empty: the suggested effort stayed 0, PoW never engaged, and a flood of ~8 in-flight handshakes locked the host out below the intro rate limit (high; verified from `tor-hsservice-0.45.0/src/pow/v1.rs` 968–1036, 1254–1280) | `tor::Admission`, derived from the built `OnionServiceConfig::enable_pow`: `Backpressure` (PoW on) reserves a handshake *and* a circuit permit **before** polling the stream, so overflow waits in Arti's effort-ordered, bounded, expiring queue; `Drop` (PoW off) keeps the eager drain-and-drop because Arti's PoW-off queue is an unbounded FIFO. `MAX_CONCURRENT_HANDSHAKES` 8 → 32, `RENDEZVOUS_TIMEOUT` 60 s → 30 s; `RendezvousLimits` + `TorNode::publish_with_limits` (tests; zero budgets refused); `tornect host` prints the budget and policy | `listener::backpressure_does_not_poll_the_request_stream_while_the_budget_is_full` (poll-counting scripted stream: no poll while the one slot is held, the waiting request is served when it frees), `drop_policy_takes_every_request_and_drops_the_overflow`, `admission_follows_the_pow_setting_and_defaults_match_the_constants`; live `live_rendezvous_backpressure` below |
| `cargo xtask verify` red: `TORNECT_PLAN.md` ≠ `docs/PLAN.md` (medium + high) | `cp TORNECT_PLAN.md docs/PLAN.md`. The root copy is the envelope track's newer revision (positional CBOR array, integer `Kind`s, `prev+1` `msg_id`, `fuzz/` in the repo map); every line only in `docs/PLAN.md` was older wording of the same §B.2/§B.3/§B.8 paragraphs (checked with `diff`, nothing track-1-specific). If the envelope track edits the plan again before the commit, the same `cp` re-syncs | gate output below |
| `StreamRequest::reject(End DONE)` had no deadline while `accept` had one (low) | Both under `ACCEPT_TIMEOUT` (10 s); expiry is `StreamOutcome::Failed` and logged | straight-line change into the verified `reject`; docs |
| Client-side `OnionStream` had no write-stall bound: `shutdown()` on a credit-withholding host could hang (low) | Every `OnionStream` carries the `StallTimer` (`STREAM_WRITE_TIMEOUT` 30 s); `OnionStream::new` and `served` share `with_guard` | existing `stall_timer_fails_a_write_with_no_progress_and_resets_on_progress`; live roundtrip below (client `shutdown()` goes through it) |
| Three residual fingerprint differences from an Arti reverse-proxy host (low) | Recorded as accepted in decision M1-2 and the listener module docs (idle circuit torn down after 30 s, 5th stream tears the circuit down, CLI's 65th session closed after `CONNECTED`) | — |
| No NEEDS-DEVICE rows for the Arti state/keystore on Windows and macOS (low) | Two rows with recipes in `docs/VERIFICATION.md`. Checking the claim behind them corrected `docs/research/arti.md` §13.7: `fs-mistrust` checks **no** permissions or owners on Windows (`fs-mistrust-0.15.1/src/imp.rs` 138 is `#[cfg(target_family = "unix")]`, README 218 "On Windows, we accept all file permissions and owners") — the note had claimed an ACL check; `hashx` falls back to its interpreter if the JIT mapping fails (`hashx-0.9.1/src/lib.rs` 76) | — |
| Stale API names in `Cargo.toml` / `docs/DEPENDENCIES.md` (low) | `tor-persist` row and comment now say `StateDirectory::acquire_instance` + `InstanceStateHandle::purge`; `tor-keymgr` row adds `list_matching`, `remove_entry`, `KeyPathPattern::Arti` | — |
| Residual DoS exposure omitted the handshake choke point (low) | M1-4 and the module docs state it with numbers for both policies (≈ 1 dead-RP introduction/s fills 32 × 30 s; ≈ 0.5 rendezvous/s fills 64 × 120 s) | — |

Found while running the live gate, outside the review: right after a warm
bootstrap, `TorNode::connect` failed with `BootstrapRequired` ("Cannot select
vanguard with unbootstrapped vanguard manager") — Arti reports
`ready_for_traffic` a moment before its vanguard manager (every onion-service
circuit goes through it) has consumed the directory. `connect` now retries that
error every 500 ms for up to 10 s; the second run below hit it three times
(`review3-live2.log` lines 30–46, 168), each resolved by the first retry. The
first live run of this round (`review3-live.log`, 00:12 UTC) also lost one of
three rendezvous to a Tor-side circuit failure ("Could not connect rendezvous
circuit" — the host's two attempts to reach that client's rendezvous point
failed within 1.6 s, and the client waited out its 60 s), so the backpressure
test now lets each client retry `connect()` up to three times, as a user would.

Live runs on the fixed tree (`target/tornect-test/review3-live2.log`, warm
`target/tornect-test/live/{host,client}`, `--test-threads=1`,
`TORNECT_LOG=warn,tornect_signal=debug,tor_hsservice::pow=debug,tor_hsclient::pow=debug,tor_hsclient::connect=debug`):

```
2026-08-29T00:16:23Z  live_rendezvous_backpressure   (host budget: 1 handshake, 1 live circuit, 2 s idle; 3 parallel connects)
[  0.0s] host launched 6blvfapklvbcui4mdci7ciyiqjub6gpmpy5kiu4qa53biu7bzub43cid.onion with a one-slot budget (Backpressure)
[  1.2s] client bootstrapped
00:16:31  tor_hsclient::connect: attempt failed error=Introduction point #1 reported error in its INTRODUCE_ACK: NOT_RECOGNIZED
00:16:34  tor_hsclient::pow::v1: beginning solve, Effort(8)
00:16:34  tor_hsclient::pow::v1: solve complete, Ok(()) Effort(8) duration=11ms (ratio: 1.375 ms)
00:16:35  tornect_signal::tor::listener: rendezvous established
[ 13.1s] host accepted stream 1/3; holding it for 5 s
[ 13.4s] client 2 connected (attempt 1)
[ 18.7s] client 2 closed by the host
00:16:43  tornect_signal::tor::listener: rendezvous circuit closed reason=Idle
00:16:44  tornect_signal::tor::listener: rendezvous established
[ 21.3s] host accepted stream 2/3; holding it for 5 s
[ 21.6s] client 1 connected (attempt 1)
[ 26.6s] client 1 closed by the host
00:16:52  tornect_signal::tor::listener: rendezvous circuit closed reason=Idle
00:16:52  tornect_signal::tor::listener: rendezvous established
[ 29.5s] host accepted stream 3/3; holding it for 5 s
[ 29.8s] client 3 connected (attempt 1)
[ 34.8s] client 3 closed by the host
[ 34.8s] every client was served (0 Tor-side connect failure(s) retried)
[ 34.8s] gap between accepts 1 and 2: 8.2 s
[ 34.8s] gap between accepts 2 and 3: 8.3 s
test live_rendezvous_backpressure ... ok

2026-08-29T00:16:59Z  live_tor_roundtrip
[  0.0s] host launched 6blvfapklvbcui4mdci7ciyiqjub6gpmpy5kiu4qa53biu7bzub43cid.onion (Backpressure, 32 handshakes / 64 circuits)
[  1.1s] client bootstrapped
[ 14.4s] client connected
[ 15.4s] ping 1 rtt 976 ms
[ 16.1s] ping 2 rtt 700 ms
[ 16.7s] ping 3 rtt 623 ms
[ 17.0s] host answered 3 ping(s)
test live_tor_roundtrip ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 52.82s
LIVE_EXIT=0 2026-08-29T00:17:16Z
```

No `rendezvous request dropped` line in either test. The requests that found the
one slot taken waited in Arti's queue and came out one per 8.2–8.3 s (5 s hold +
2 s idle + ~1 s handshake); the effort-8 request is Arti's own client retrying
after a stale intro point refused it (`tor-hsclient-0.45.0/src/connect.rs` 1093),
verified by the host's PoW manager and served through the same queue. The
suggested-effort *ramp* was not reached in 35 s (`pow_manager.json` still says
`"suggested_effort": 0`; Arti recomputes every 300 s and needs
`num_enqueued_gte_suggested >= num_dequeued / busy_fraction`) — recorded as OPEN
with a recipe in `docs/VERIFICATION.md`.

Gate on the fixed tree, plan copies synced (`target/tornect-test/review3-verify.log`):

```
2026-08-29T00:17:36Z CARGO_BUILD_JOBS=3 TMPDIR=$PWD/target/tmp cargo xtask verify
==> plan sync (TORNECT_PLAN.md == docs/PLAN.md)                          ok
==> forbidden dependencies absent (aws-lc-rs, aws-lc-sys, openssl-sys)   ok
==> cargo fmt --all -- --check                                            ok (0.1s)
==> cargo clippy --workspace --all-targets -- -D warnings                 ok (22.7s)
==> cargo test --workspace                                                ok (127.4s)
    tornect-core: 26 passed; tornect-signal: 43 passed; live: 2 ignored
==> cargo doc --workspace --no-deps (RUSTDOCFLAGS=-D warnings)            ok (16.9s)
verify: all gates green            (VERIFY_EXIT=0 at 00:20:24Z)
```

`tornect-signal` is at 43 unit tests: framing 8, ping 10, crypto provider 1,
config 3, identity 8, node 2, listener 11 (the three admission tests are new).

## Environment gotchas found while running this

- `/tmp` on the VM is a quota-limited tmpfs shared with other tracks' probe builds.
  `zstd-sys` failed with `fatal error: error writing to /tmp/ccjnq8qT.s: Disk quota
  exceeded` because `cc` puts its temporaries there. **Set
  `TMPDIR=/home/mx/Tornect/target/tmp`** (or any directory outside `/tmp`) for cargo
  builds on this machine. Tor state/caches already live under `target/tornect-test/`.
  Later in the session the same quota also broke the Claude Code Bash tool's own
  output capture (which lives under `/tmp/claude-1000`); command output was routed to
  files under `target/tornect-test/` instead.
- The host reported `ping session ended: I/O error: Stream not connected` when the
  client dropped its stream without a graceful close (Arti maps an abrupt `END` to
  `NotConnected`). Fixed in run 3: the client calls `shutdown()` on the stream (Arti
  then sends END with reason MISC, which the host's `OnionStream` reports as EOF) and
  `ping::serve` treats peer-gone I/O errors as the normal end of a session; the client
  side explains a host that vanishes mid-session (run 4).
- Arti's status stream reports `Problem::Ipt([])` (an empty error list) while starting
  up; it was shown as "introduction point errors (0)". Fixed in run 3: empty lists are
  not problems, and status is only re-published when it changes.
- Descriptor reachability on this network: `REACHABLE` (`State::Running`) came 61–73 s
  after launch on cold/warm starts where the descriptor had to be re-uploaded, and
  10–14 s when Arti could reuse the previous run's introduction points and descriptor.
  Rendezvous took 6.6–9.0 s in every successful run; one of ten connects timed out
  (run 6) with matching guard/circuit failures on the host side.

## Independent verification (remediation pass, 2026-08-29 02:46–03:02 UTC)

Reproduced from scratch by a second session that did not reuse anything above: new
state directories (`target/tornect-test/v1` host, `v2` client, both `rm -rf`'d first),
same machine, same debug profile, default features (`tor-pow` on), default log filter
(`info,…,tornect_signal=debug,arti=warn,tor=warn`). Raw logs (git-ignored):
`target/tornect-test/v-verify.log`, `v-host1.log`, `v-ping1.log`, `v-host2.log`,
`v-ping2-{1,2,3}.log`. Everything below is copied from those files; the only
lines left out are `DEBUG` bootstrap-progress lines.

Tornect ID under test: `l6tnrcetlwnqif75bbbovemd35lo73uadq47qwmgp2ivajmgd2aiauad.onion`
(Arti nickname `tornect-l6tnrcet`).

### Gate

`CARGO_BUILD_JOBS=3 TMPDIR=$PWD/target/tmp cargo xtask verify`, exit 0
(artifacts were warm, so the timings are cache hits, but every gate ran):

```
==> plan sync (TORNECT_PLAN.md == docs/PLAN.md)                          ok
==> forbidden dependencies absent (aws-lc-rs, aws-lc-sys, openssl-sys)   ok
==> cargo fmt --all -- --check                                            ok (0.3s)
==> cargo clippy --workspace --all-targets -- -D warnings                 ok (0.4s)
==> cargo test --workspace                                                ok (1.7s)
    tornect_core: 26 passed; tornect_signal: 43 passed;
    tests/live.rs: live_rendezvous_backpressure + live_tor_roundtrip ignored (need --ignored);
    every other crate: 0 tests
==> cargo doc --workspace --no-deps (RUSTDOCFLAGS=-D warnings)            ok (0.3s)
verify: all gates green
```

### Timeline

| UTC | Event | Source |
|---|---|---|
| 02:46:44 | `TORNECT_HOME=…/v1 timeout 600 cargo run -q -p tornect -- host` started; `cargo run` rebuilt the Arti graph for the binary's feature set (~2 min 14 s) before the process started | shell |
| 02:48:58.33 | new Tornect ID generated (`v1/state/keys`); Tor client created (`v1/state/arti`) | `v-host1.log` |
| 02:48:58.34 | onion service launched (`admission=Backpressure max_handshakes=32 max_live_circuits=64`); **`Tornect ID: l6tnrcet…auad.onion`** printed 2 ms after client creation, before bootstrap | `v-host1.log` |
| 02:49:17.50 | `Tor bootstrap complete` (cold: **19.2 s**); status `Bootstrapping` | `v-host1.log` |
| 02:52:33.73 | `WARN tor_circmgr::hspool: Too many preemptive onion service circuits failed; waiting a while.` | `v-host1.log` |
| 02:54:12 | 5-minute poll window for `REACHABLE` expired (started 02:49:12) — **not reachable yet**; ping started anyway per the recipe | shell |
| 02:54:23.44 | `WARN tor_hsservice::publish::reactor: failed to upload descriptor … error=Timeout exceeded` (one HSDir), then `onion service status state=DegradedReachable reachable=true problem="descriptor upload failed (1 attempt(s))"` → **`REACHABLE`** — **325 s after launch** | `v-host1.log` |
| 02:54:23.65 | `TORNECT_HOME=…/v2 timeout 300 cargo run -q -p tornect -- ping <id> --count 5` (fresh `v2`) | `v-ping1.log` |
| 02:54:32.33 | client `Tor bootstrap complete` (cold: **8.7 s**) | `v-ping1.log` |
| 02:55:20.01 | `onion stream open` — **`connected in 47.7 s`** | `v-ping1.log` |
| 02:55:20–24 | `rtt 844.6 / 940.4 / 976.6 / 1101.3 / 873.5 ms` → **`PING OK n=5 min/avg/max=844.6/947.3/1101.3 ms`**, exit 0; host: `client connected over Tor`, `answered ping #1`…`#5`, `client disconnected after 5 ping(s)` | `v-ping1.log`, `v-host1.log` |
| 02:55:32 | `pkill -INT -x tornect` → `Ctrl-C: shutting down`, `onion service stopped`, `Tor node shutting down`, then `WARN tornect_signal::tor::node: muted a tokio teardown panic (Arti PoW-manager blocking thread; …)` at +253 ms; process gone; `v1/state/arti/state/{guards,circuit_timeouts}.json` mtime 02:55:32 | `v-host1.log`, `ls` |
| 02:55:50 | host run 2 started on the **same** `v1` (`v-host2.log`) | shell |
| 02:55:51.26 | onion service launched; **`Tornect ID: l6tnrcet…auad.onion` — identical** | `v-host2.log` |
| 02:55:52.20 | `Tor bootstrap complete` (warm: **0.95 s**); status `Bootstrapping` | `v-host2.log` |
| 02:59:04 | 180 s `REACHABLE` poll expired (status still `Bootstrapping`); ping started anyway | shell |
| 02:59:13–03:00:14 | ping attempt 1 (warm `v2`, bootstrap 0.9 s): **`Tor did not answer in time. Check the network on both ends and retry.`** after the 60 s `CONNECT_TIMEOUT`, exit 1 | `v-ping2-1.log` |
| 03:00:15–03:01:16 | ping attempt 2: same timeout, exit 1. Host meanwhile: `hspool: Too many preemptive onion service circuits failed` (03:00:33), two `failed to upload descriptor … Timeout exceeded` (03:01:05) | `v-ping2-2.log`, `v-host2.log` |
| 03:01:16.59 | ping attempt 3 (bootstrap 0.9 s) | `v-ping2-3.log` |
| 03:01:23.24 | `onion stream open` — **`connected in 5.7 s`** | `v-ping2-3.log` |
| 03:01:23–26 | `rtt 550.1 / 539.5 / 549.9 / 617.1 / 546.7 ms` → **`PING OK n=5 min/avg/max=539.5/560.7/617.1 ms`**, exit 0; host `answered ping #1`…`#5`, `client disconnected after 5 ping(s)` | `v-ping2-3.log`, `v-host2.log` |
| 03:01:37.91 | `pkill -INT -x tornect` → `onion service stopped`, `Tor node shutting down`; `guards.json` + `circuit_timeouts.json` rewritten at **03:01:38.171** (253 ms later = the exit flush); process gone by 03:01:38 | `v-host2.log`, `ls --full-time` |
| 03:01:40 | `tornect id --json` on `v1` → `{"created":false,…,"tornect_id":"l6tnrcetlwnqif75bbbovemd35lo73uadq47qwmgp2ivajmgd2aiauad.onion"}` | shell |

Run 2 **never printed `REACHABLE`** in its 5 min 47 s of life: Arti's status stayed
`Bootstrapping` (its publish reactor was still timing out on individual HSDir uploads
when the client got through), yet the client connected and was served. `REACHABLE`
is Arti's *self-assessment* of the descriptor upload, not a prerequisite for
connections; a run-1-style `DegradedReachable` is reported only when a full upload
round finishes.

### Log excerpts

`v-host1.log` (run 1, cold; `DEBUG` lines removed):

```
generated a new Tornect ID (stored in /home/mx/Tornect/target/tornect-test/v1/state/keys)
bootstrapping Tor (~30 s cold, a few seconds with a warm cache)...
2026-08-29T02:48:58.338471Z  INFO tornect_signal::tor::node: Tor client created state_dir=/home/mx/Tornect/target/tornect-test/v1/state/arti
publishing onion service (PoW defense on; reachable after descriptor upload, typically ~10 s past bootstrap, up to 2 min on a cold start)...
tor: bootstrap   0%
2026-08-29T02:48:58.338666Z  INFO tornect_signal::tor::identity: installing host identity into Arti keystore nickname=tornect-l6tnrcet
2026-08-29T02:48:58.340412Z  INFO tornect_signal::tor::node: onion service launched address=l6tnrcetlwnqif75bbbovemd35lo73uadq47qwmgp2ivajmgd2aiauad.onion nickname=tornect-l6tnrcet admission=Backpressure max_handshakes=32 max_live_circuits=64
Tornect ID: l6tnrcetlwnqif75bbbovemd35lo73uadq47qwmgp2ivajmgd2aiauad.onion
rendezvous budget: 32 handshakes, 64 live circuits; beyond that requests wait in Tor's proof-of-work queue
onion service: Shutdown
tor: bootstrap   8%
tor: bootstrap  15%
tor: bootstrap  36%
tor: bootstrap  45%
tor: bootstrap 100%
2026-08-29T02:49:17.503099Z  INFO tornect_signal::tor::node: Tor bootstrap complete
2026-08-29T02:49:17.503984Z  INFO tornect_signal::tor::listener: onion service status state=Bootstrapping reachable=false problem="-"
onion service: Bootstrapping
tor: ready
2026-08-29T02:52:33.733341Z  WARN tor_circmgr::hspool: Too many preemptive onion service circuits failed; waiting a while.
2026-08-29T02:54:23.442114Z  WARN tor_hsservice::publish::reactor: failed to upload descriptor for service tornect-l6tnrcet (hsdir_id=$82c2ce2bb4c93d4fca2d7f99ed23dbf5335eedf7, hsdir_rsa_id=$82c2ce2bb4c93d4fca2d7f99ed23dbf5335eedf7) error=Timeout exceeded
2026-08-29T02:54:23.442195Z  INFO tornect_signal::tor::listener: onion service status state=DegradedReachable reachable=true problem="descriptor upload failed (1 attempt(s))"
REACHABLE
onion service reachable (DegradedReachable); waiting for pings
client connected over Tor
answered ping #1
answered ping #2
answered ping #3
answered ping #4
answered ping #5
client disconnected after 5 ping(s)
Ctrl-C: shutting down
2026-08-29T02:55:32.740474Z  INFO tornect_signal::tor::listener: onion service stopped address=l6tnrcetlwnqif75bbbovemd35lo73uadq47qwmgp2ivajmgd2aiauad.onion
2026-08-29T02:55:32.740499Z  INFO tornect_signal::tor::node: Tor node shutting down
2026-08-29T02:55:32.993604Z  WARN tornect_signal::tor::node: muted a tokio teardown panic (Arti PoW-manager blocking thread; tor-hsservice pow/v1.rs) during runtime shutdown
```

`v-ping1.log` (fresh `v2`):

```
bootstrapping Tor (~30 s cold, a few seconds with a warm cache)...
2026-08-29T02:54:23.647991Z  INFO tornect_signal::tor::node: Tor client created state_dir=/home/mx/Tornect/target/tornect-test/v2/state/arti
tor: bootstrap   0%
tor: bootstrap   8%
tor: bootstrap  15%
tor: bootstrap  36%
tor: bootstrap  45%
tor: bootstrap 100%
2026-08-29T02:54:32.331195Z  INFO tornect_signal::tor::node: Tor bootstrap complete
tor: ready
connecting to l6tnrcetlwnqif75bbbovemd35lo73uadq47qwmgp2ivajmgd2aiauad.onion (rendezvous usually takes 5-30 s, up to 60 s)...
2026-08-29T02:54:32.331263Z  INFO tornect_signal::tor::node: connecting to host over Tor host=l6tnrcetlwnqif75bbbovemd35lo73uadq47qwmgp2ivajmgd2aiauad.onion
2026-08-29T02:55:20.008906Z  INFO tornect_signal::tor::node: onion stream open host=l6tnrcetlwnqif75bbbovemd35lo73uadq47qwmgp2ivajmgd2aiauad.onion
connected in 47.7 s
ping 1/5: rtt 844.6 ms
ping 2/5: rtt 940.4 ms
ping 3/5: rtt 976.6 ms
ping 4/5: rtt 1101.3 ms
ping 5/5: rtt 873.5 ms
PING OK n=5 min/avg/max=844.6/947.3/1101.3 ms
2026-08-29T02:55:24.745688Z  INFO tornect_signal::tor::node: Tor node shutting down
```

`v-host2.log` (run 2 after SIGINT, same `v1`, warm; `DEBUG` lines removed):

```
bootstrapping Tor (~30 s cold, a few seconds with a warm cache)...
2026-08-29T02:55:51.254313Z  INFO tornect_signal::tor::node: Tor client created state_dir=/home/mx/Tornect/target/tornect-test/v1/state/arti
publishing onion service (PoW defense on; reachable after descriptor upload, typically ~10 s past bootstrap, up to 2 min on a cold start)...
tor: bootstrap   0%
2026-08-29T02:55:51.257217Z  INFO tornect_signal::tor::node: onion service launched address=l6tnrcetlwnqif75bbbovemd35lo73uadq47qwmgp2ivajmgd2aiauad.onion nickname=tornect-l6tnrcet admission=Backpressure max_handshakes=32 max_live_circuits=64
Tornect ID: l6tnrcetlwnqif75bbbovemd35lo73uadq47qwmgp2ivajmgd2aiauad.onion
rendezvous budget: 32 handshakes, 64 live circuits; beyond that requests wait in Tor's proof-of-work queue
onion service: Shutdown
tor: bootstrap  30%
tor: bootstrap  85%
2026-08-29T02:55:52.203920Z  INFO tornect_signal::tor::node: Tor bootstrap complete
2026-08-29T02:55:52.208001Z  INFO tornect_signal::tor::listener: onion service status state=Bootstrapping reachable=false problem="-"
onion service: Bootstrapping
tor: bootstrap  30%
tor: bootstrap  85%
tor: bootstrap  93%
tor: bootstrap 100%
tor: ready
2026-08-29T03:00:33.718875Z  WARN tor_circmgr::hspool: Too many preemptive onion service circuits failed; waiting a while.
2026-08-29T03:01:05.776000Z  WARN tor_hsservice::publish::reactor: failed to upload descriptor for service tornect-l6tnrcet (hsdir_id=$893bb86b0437c993db752bef1b90c62fa994899f, hsdir_rsa_id=$893bb86b0437c993db752bef1b90c62fa994899f) error=Timeout exceeded
2026-08-29T03:01:05.876745Z  WARN tor_hsservice::publish::reactor: failed to upload descriptor for service tornect-l6tnrcet (hsdir_id=$82d719464e4ed7bab99b21bc69e5fc3b74f28f10, hsdir_rsa_id=$82d719464e4ed7bab99b21bc69e5fc3b74f28f10) error=Timeout exceeded
client connected over Tor
answered ping #1
answered ping #2
answered ping #3
answered ping #4
answered ping #5
client disconnected after 5 ping(s)
Ctrl-C: shutting down
2026-08-29T03:01:37.914882Z  INFO tornect_signal::tor::listener: onion service stopped address=l6tnrcetlwnqif75bbbovemd35lo73uadq47qwmgp2ivajmgd2aiauad.onion
2026-08-29T03:01:37.914905Z  INFO tornect_signal::tor::node: Tor node shutting down
2026-08-29T03:01:38.167675Z  WARN tornect_signal::tor::node: muted a tokio teardown panic (Arti PoW-manager blocking thread; tor-hsservice pow/v1.rs) during runtime shutdown
```

`v-ping2-1.log` (attempt 1; attempt 2 is identical apart from timestamps):

```
2026-08-29T02:59:13.829374Z  INFO tornect_signal::tor::node: Tor client created state_dir=/home/mx/Tornect/target/tornect-test/v2/state/arti
2026-08-29T02:59:14.775764Z  INFO tornect_signal::tor::node: Tor bootstrap complete
connecting to l6tnrcetlwnqif75bbbovemd35lo73uadq47qwmgp2ivajmgd2aiauad.onion (rendezvous usually takes 5-30 s, up to 60 s)...
Error: Tor did not answer in time. Check the network on both ends and retry.

Caused by:
    timed out while connecting to the host over Tor
```

`v-ping2-3.log` (attempt 3):

```
2026-08-29T03:01:16.590503Z  INFO tornect_signal::tor::node: Tor client created state_dir=/home/mx/Tornect/target/tornect-test/v2/state/arti
2026-08-29T03:01:17.533572Z  INFO tornect_signal::tor::node: Tor bootstrap complete
2026-08-29T03:01:23.240313Z  INFO tornect_signal::tor::node: onion stream open host=l6tnrcetlwnqif75bbbovemd35lo73uadq47qwmgp2ivajmgd2aiauad.onion
connected in 5.7 s
ping 1/5: rtt 550.1 ms
ping 2/5: rtt 539.5 ms
ping 3/5: rtt 549.9 ms
ping 4/5: rtt 617.1 ms
ping 5/5: rtt 546.7 ms
PING OK n=5 min/avg/max=539.5/560.7/617.1 ms
2026-08-29T03:01:26.043776Z  INFO tornect_signal::tor::node: Tor node shutting down
```

Persisted layout after both runs (`v1`, 148 KB state, 46 MB cache) matches the `h1`
listing above one-for-one: `state/keys/{host,device}-identity.ed25519-seed.secret`,
`state/arti/keystore/hss/tornect-l6tnrcet/{ks_hs_id, 2× ks_hs_blind_id+2069{3,4}_…,
2× ks_hs_desc_sign+…, ipts/{k_hss_ntor,k_sid}+<lid> ×3}`,
`state/arti/hss/tornect-l6tnrcet/{ipts.json, iptpub.json, iptreplay/ ×3,
pow_manager.json, pow_nonces/ ×2}`, `state/arti/state/{guards,circuit_timeouts}.json`.

### Verdict and what differed from the first pass

- **Pass**: gate green; the ID printed by run 1, run 2 and `tornect id` is the same
  56-character address; 5 + 5 pings answered over the live network; SIGINT exits
  cleanly both times with the state flush 253 ms later.
- **Tor was slow/flaky during this pass** and the numbers are well outside the
  earlier ones: run 1 reached `REACHABLE` (as `DegradedReachable`, one HSDir upload
  timed out) **325 s** after launch instead of 61–73 s; run 2 never reported it in
  5 min 47 s; the first cold connect took 47.7 s; and 2 of the 4 `tornect ping`
  connects timed out at 60 s (`hspool: Too many preemptive onion service circuits
  failed` on the host both times), succeeding on the third try with a 5.7 s
  rendezvous. The CLI's "up to 2 min on a cold start" hint and CLAUDE.md's "≈ 70 s"
  are best-case figures, not bounds. Nothing in Tornect's logs attributes the
  failures to anything but the Tor side (guard/circuit build failures); the retry
  advice in the error message was correct.
- `Flushed persistent state at exit.` no longer appears in the logs: the default
  filter is now `…,arti=warn,tor=warn`, which drops `tor_circmgr`'s `INFO` line. The
  flush itself is evidenced by the `guards.json` / `circuit_timeouts.json` mtimes
  (02:55:32 and 03:01:38.171, each ≈ 250 ms after `Tor node shutting down`).
- The muted tokio teardown panic is now surfaced as one `WARN` line
  (`muted a tokio teardown panic …`) on every host exit — expected per the first
  security review's fix, but visible to users on stderr.
