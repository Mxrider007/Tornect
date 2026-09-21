# Research: reaching Tor where it is blocked (obfs4 → Snowflake)

**Status:** verified 2026-09-21 (research_verifier sub-agent against the local Arti 0.45.0
sources, tor-browser-build and the Tor Browser 15.0.23 release; live runs on mx-vm).
Full report with every citation and verbatim evidence files:
`/home/mx/kore_project_V3/agents/devops/reports/sub/2026-09-21_SUB_RESEARCH_VERIFIER_tor_bridges.md`
(+ `…/2026-09-21_tor_bridges_evidence/`). Decision: `docs/notes/decisions.md` M1-38.
Code: `crates/tornect-signal/src/tor/bridges.rs`, `TorNode::start_auto`.

## 1. Arti 0.45 API

- **Cargo:** add `pt-client` to `arti-client` (`arti-client-0.45.0/Cargo.toml:197-202`); it
  implies `bridge-client` (`:59-62`) and pulls `tor-ptmgr` 0.45.0 (MIT OR Apache-2.0). Nothing in
  the chain is experimental. Built on mx-vm 2026-09-21 (partial Arti rebuild, 3 min 31 s).
- **Bridges** from bridge-line strings: `let b: BridgeConfigBuilder = line.parse()?;
  builder.bridges().bridges().push(b);` (`tor-guardmgr` `bridge/config.rs:376-421`; a leading
  `Bridge ` word is accepted). The built-in `meek_lite` line has no fingerprint → rejected by
  Arti (needs the RSA identity); Tornect does not use it.
- **Managed transport:** `TransportConfigBuilder::default().protocols(vec![…]).path(
  CfgPath::new_literal(abs_path))`, pushed to `builder.bridges().transports()`. `new_literal`
  expands nothing (no `~`, no `${…}`). One config may list several protocols; one lyrebird
  process then serves them all and Arti requires a `CMETHOD` for each before `CMETHODS DONE`.
  `run_on_startup` is accepted but ignored in 0.45: PTs start lazily on first use.
- **Switch:** `builder.bridges().enabled(BoolOrAuto::Explicit(true|false))`.
- **PT state:** `<state_dir>/pt_state/lyrebird/` (0700 parent via fs-mistrust).
- **Supervision (tor-ptmgr `ipc.rs`):** the PT gets 30 s to answer `VERSION`/`CMETHOD`s; stdout
  `LOG` lines map to tracing; on EOF or an unparsable line the PT is dropped and relaunched on the
  next use (no backoff, Arti #678). Dropping does not kill the child: the stdout thread closes
  stdin (`TOR_PT_EXIT_ON_STDIN_CLOSE=1`) when it next notices, waits 5 s, then kills. A silent
  lyrebird can outlive its client until Tornect exits (lyrebird also exits on parent change).

## 2. One fresh client per rung (not `reconfigure`)

`TorClient::reconfigure` can switch direct ↔ bridges, but the PT reactor ignores reconfigure
(#2634), dirmgr keeps sleeping through its backoff, and chanmgr's "ever connected" status never
resets. And **a bridged client that cannot take `state/state.lock` fails permanently** with
`GuardMgrConfigError::NoLock("bridges configured")` (`tor-guardmgr lib.rs:368-375, 924-928`) —
Arti's background tasks keep the old client's managers (and the lock) alive until its runtime
shuts down. So each rung is a fresh `TorClient` on its **own tokio runtime**, torn down with
`shutdown_runtime` before the next rung; state and cache dirs are reused sequentially. Guard
state keeps separate `default` / `restricted` / `bridges` sets, and reachability is not
persisted, so a failed rung does not poison the next. The onion identity is unaffected
(Tornect installs its key on every publish).

## 3. Blocking detection

`bootstrap()` returns `Ok` from a warm cache **even when the network is blocked** (progress
≥ 85 %); only `BootstrapStatus::ready_for_traffic()` is success. `blocked()` cannot report before
60 s and 6 attempts. Tornect's per-rung policy (`Rung::policy`, not measured under real
censorship): direct cap 75 s / stall 40 s, obfs4 120 s / 60 s, Snowflake 180 s / 90 s; the stall
timer ends a rung whose fraction has not grown for that long. A ladder of one rung (forced mode)
waits `tor.bootstrap_timeout_secs` with no stall cut. The rung that works is written to
`<state_dir>/tor-transport` and tried first next time (Tor Browser does the same).

## 4. Built-in bridges

Verbatim from tor-browser-build `projects/tor-expert-bundle/pt_config.json` (main `95c6131b`,
byte-identical at tag `tbb-15.0.23-build1`), and cross-checked byte for byte on 2026-09-21
against the `pt_config.json` inside the GPG-verified tor-expert-bundle 15.0.23: 7 obfs4 lines,
2 Snowflake lines (domain-fronted broker `https://1098762253.rsc.cdn77.org/`, fronts
`app.datapacket.com,www.datapacket.com`, 8 STUN servers, `utls-imitate=hellorandomizedalpn`;
387 bytes of arguments, under Arti's 510-byte SOCKS limit). They are public — a censor can list
them — so `tor.bridge_lines` (private bridges from https://bridges.torproject.org) **replace**
the built-ins of their transport (decision M1-40). An earlier version tried them first and kept the
built-ins behind them. Arti's guard selection then still contacted public bridges beside the
private one: descriptor fetches go to the first two guards, directory fetches spread over three,
and confirmed guards from earlier runs lead. A censor listing the public bridges could therefore find
the private one by correlation (SLICE-A1 A1-1). `webtunnel` lines are accepted on the obfs4 rung too
(lyrebird serves them); there are no built-in webtunnel bridges.

## 5. The PT binary: lyrebird (obfs4 **and** Snowflake)

Since tor-browser-build `efdc0f34` / `284a7380` (2025-03/04) **there is no `snowflake-client`
binary**: `ClientTransportPlugin snowflake exec ${pt_path}lyrebird`. One `lyrebird` covers
obfs4, Snowflake and webtunnel.

- Source: Tor Browser **15.0.23** (stable, 2026-09-15) tor-expert-bundle, lyrebird **0.8.1**.
  `https://archive.torproject.org/tor-package-archive/torbrowser/15.0.23/tor-expert-bundle-{linux,windows}-x86_64-15.0.23.tar.gz`
  (+ `.asc`; `sha256sums-signed-build.txt` + `.asc`).
- Signing key: Tor Browser Developers, primary **EF6E 286D DA85 EA2A 4BA7 DE68 4E2C 6E87 9329
  8290** (signing subkey `CAAE408A…` expires 2026-10-26 — pin the primary). Verified on mx-vm
  2026-09-21: `gpgv` "Good signature" on both tarballs and the sums file; sums match.
- Pins (`packaging/pt/SOURCES.md`): linux tarball
  `08d49de27f542b8f73e2014e064d8320562b5d20019c03d4725c5a5249d97985`, windows tarball
  `231dad6b9cb401a54c260db7046965ef04e4f72ff071b140d423fb5da281ab1e`; extracted `lyrebird`
  `ee13ec15…`, `lyrebird.exe` `6e218e85…` (PE32+ **console** subsystem).
- Licences: lyrebird BSD-2-Clause **plus GPL-3.0-or-later code** (`meeklite/transport.go`), so
  redistributing it means offering its source (the tarball's `docs/lyrebird.txt` + the upstream
  tag); Snowflake code BSD-3-Clause. Both compatible with Tornect's GPL-3.0-or-later.

## 6. Windows

- tor-ptmgr spawns the PT with plain `Command` (no `CREATE_NO_WINDOW`); lyrebird.exe is a
  console program. A **console-subsystem** Tornect shares its console with the child (no extra
  window) — today's binary. A future `windows_subsystem = "windows"` GUI build would pop a console
  per PT; the fix is to launch lyrebird ourselves with `CREATE_NO_WINDOW` and hand Arti an
  unmanaged `proxy_addr`, or patch tor-ptmgr `ipc.rs:571` upstream. Not observed on Windows yet.
- `std::process::Command` appends `.exe` when missing; pass the explicit absolute path anyway.

## 7. Gotchas (from code; watch for them live)

- Arti gives a PT channel a fixed 10 s for connect + handshake (`tor-chanmgr builder.rs:198-203`);
  Snowflake's own per-proxy timeouts are also 10 s ⇒ fragile under load.
- goptlib octal-escapes quotes/non-ASCII in PT log lines; Arti fails to parse such a line and
  drops the PT (Arti #609). lyrebird forwards raw Snowflake errors, which may contain quotes.
- Hosting an onion service over bridges works by code path (the bridge is the first hop of every
  circuit, onion-service circuits included); no open Arti issue found. Verified live for the
  client side on 2026-09-21; the host side over bridges is part of the live session test.

## 8. Live results (mx-vm, 2026-09-21, fresh `TORNECT_HOME` each, cold cache)

| rung (forced with `--bridges`) | result | time |
|---|---|---|
| `off` (direct) | `TOR OK via direct` | 14.3 s |
| `obfs4` (7 built-in lines) | `TOR OK via obfs4` (some circuit timeouts first) | 78.2 s |
| `snowflake` (2 built-in lines) | `TOR OK via snowflake`; `guards.json` = 2 bridge guards, 0 default; `pt_state/lyrebird` present | 16.2 s |

The *fallback* path itself (direct blocked ⇒ obfs4 ⇒ Snowflake) needs a censored network to
demonstrate end to end; it is covered by the ladder unit tests and is a `NEEDS-DEVICE(censored
network)` row in `docs/VERIFICATION.md`.
