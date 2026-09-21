# Tornect — continuation report (2026-09-21, second session close)

Paste the block under **HAND-OFF** into a new session.

---

## HAND-OFF

Continue building Tornect from `/home/mx/Tornect` (private repo
https://github.com/Mxrider420z/Tornect, branch `main`, pushed at `81da800`, clean).

The operator's goal for this run:
- **A functional app on Linux and Windows.** The operator will test with one Linux and one
  Windows machine.
- **Tor with automatic obfs4 bridges when Tor is blocked, and Snowflake when obfs4 fails.**
- **The code cross-compiling for Windows.**

Scope ruling (operator, 2026-09-21): **"vertical slice first"**. That means a real Linux↔Windows
remote session end to end: Tor transport, software H.264, one capture and input backend per OS,
a minimal egui window with the consent popup, the sharing indicator and the kill switch, a
cross-built Windows binary, and packaged zips. QUIC hole punching is deferred, and m2–m6 stay
untagged until their full acceptance runs.

Read in this order before doing anything:
1. `CLAUDE.md`
2. this file
3. `docs/notes/m1-state.md` (§ *Session 2026-09-21 (2)*)
4. `docs/research/slice.md`
5. `docs/notes/decisions.md` M1-38 … M1-41 and M3-1
6. the slice review
   `/home/mx/kore_project_V3/agents/security/reports/2026-09-21_tornect_slice_review.md`

Then run `CARGO_BUILD_JOBS=3 TMPDIR=$PWD/target/tmp cargo xtask verify`. Expect **368 tests**
and `cargo deny check (offline; advisory DB 2026-08-29)` ok.

### STATE (2026-09-21, second session)

Pushed commits this session:

| Commit | What |
|---|---|
| `5523fcc` | the 8 track D fixes |
| `c868e71` | proto/input hardening |
| `38c8de5` | bridge ladder hardening + lyrebird pin |
| `110b774` | cargo-deny in the gate |
| `81da800` | a flaky test fixed |

1. **Track D: CLOSED.** All 8 distinct survivors of the 105-agent review are fixed. Each was
   re-verified against the code first, and the tests for S1, S2 and S3 fail on the old code.
   - **IPC endpoint:**
     - The CLI waits `RESPONSE_TIMEOUT` = 150 s, compile-time asserted to outlast the 120 s
       polkit dialog.
     - If an `On` answer cannot be delivered, the host turns access back off and clears the
       unseen stop token (`MutationGuard::master_off_undelivered_stop_code`).
     - Connections are served concurrently (≤ 16).
     - `PolkitReAuth` holds one dialog at a time and refuses a second at once.
   - **Admin path:**
     - The kill effect fires even when `ADMIN_RESULT` cannot be written.
     - Post-commit log lines are best-effort.
     - A failed commit logs `AdminRequest{ok:false}`.
   - **Offline CLI:** it loads the store with `GrantStore::open_offline`.
   - **polkit:** `allow_any`/`allow_inactive` = `auth_self`, so a text agent works over SSH;
     `is_challenge` is reported as "no authentication agent".
   - **Password and stop-code handling:**
     - The password is read unbuffered straight off the TTY fd into a pre-sized buffer that is
       wiped on drop; an over-long line is drained.
     - The stop code is written raw to fd 1.
     - `MasterOnPayload` and `RegStartPayload` are `ZeroizeOnDrop`.
   - **Password policy:** zxcvbn gets device/grant labels and the host name; whitespace warnings
     need a y/N; `--waive-attended-check` warns.
   - **Hand-checked:** a PTY-driven `on → grant → status`, and `tornect host` + IPC
     `status/pause/off`.
2. **Slice-range review (`7697823..efe75fa`): done.** It ran as A′: 3 read-only KORE Security
   sub-agents. The ≈ 100-agent refuted review was not approved at that size. The result was
   0 critical and 0 high. Fixed:
   - **M1-40 (`38c8de5`):**
     - Private `tor.bridge_lines` **replace** the built-ins of their transport.
     - `auto` skips direct Tor when private lines exist, and puts direct last once a bridge
       worked.
     - Forced `--bridges` runs do not learn the last-good rung.
     - lyrebird comes from next to the exe, then `$TORNECT_PT_DIR`, never `PATH`, absolute
       paths only. It must match `LYREBIRD_SHA256` (lyrebird 0.8.1), and group- or
       world-writable binaries are refused. Only an explicit `tor.pt_path` may run another build.
     - Bridge lines are reported by position only.
     - The host warns when it is reachable only over Snowflake.
     - Peer IDs are logged in their short form.
     - A Windows GNU build without `+crt-static` fails to compile.
     - Live checks: the obfs4 rung was ready in 47.6 s with the pinned binary, and a tampered
       copy was refused.
   - **M1-41 (`c868e71`):** `Bind.mac` is keyed by `HKDF-SHA256(session_token,
     "tornect/v1/tor-media-bind-key")`, pinned by an independently computed test vector.
     `SYSTEM_KEYS` (Power, Sleep, WakeUp, Eject) are refused by `Tracked`, and the input decoder
     is stricter.
   - **`110b774`:**
     - `xtask verify` runs `cargo deny --offline check` (binary under
       `target/tools/cargo-deny-0.20.2-x86_64-unknown-linux-musl/`) and prints the DB date. It
       says SKIPPED if the tool is absent.
     - `deny.toml` covers the gnullvm target and the `keyring` feature.
     - The `rsa` ignore reason is corrected.
     - Forbidden deps are checked with `--target all`.
     - `dist` builds with `--locked`.
3. **Unchanged from the previous hand-off:**
   - Bridges live-verified (direct 14.3 s, obfs4 78.2 s, Snowflake 16.2 s cold).
   - The media port 4001 and `connect_on`.
   - The `tornect-proto`, `tornect-input` and `tornect-codec` crates.
   - The Windows cross-build route: llvm-mingw 20260908, `x86_64-pc-windows-gnullvm`,
     OpenH264's C++ links.

### NEXT, in order

1. **Wire `serve_host` into `tornect host`.** This has been the critical path since 2026-09-05.
   - Seams to fill:
     - `HostDeps::unattended` = `UnattendedAuth` + `GuardAdmin`
     - `stop_token` = `EmergencyStop`
     - `audit` = `HostAudit`
     - `trusted` = the real store
     - `consent` = a CLI/GUI prompt
     - `kill` shared with the IPC `HostContext`
   - Add a new `SessionSink` seam, called right after `SESSION_ACCEPT` (session id, token,
     `th_final`, mode, label) and at session end.
   - **Fix `KillSwitch` first:** it latches, so after one kill every later session is ended. Make
     it per-session or resettable.
   - The client side: `connect` → `send_tor_fallback` →
     `connect_on(MEDIA_PORT, same Isolation)` → `Bind`, then keep signaling alive with `PING`s
     (host idle timeout 90 s).
2. **`tornect-capture`:**
   - a `VideoSource` trait (blocking `next_frame`, tight BGRx), plus a synthetic test card;
   - X11: GetImage + XFIXES cursor;
   - Wayland: one RemoteDesktop portal session with ScreenCast sources (`ashpd`), PipeWire via
     **dlopen**. The layouts and the 232-byte EnumFormat pod are in `docs/research/slice.md` §4;
     Mutter offers only BGRx/BGRA; always requeue buffers. The portal session also yields the
     input sink.
   - Windows: GDI `BitBlt`.
3. **`tornect-session`.** It must meet the review's requirements (SLICE-A2 A2-3/A2-4/A2-6, A1 G3):
   - the view-only gate before `Input` is even decoded;
   - single-use `Bind` with a deadline;
   - one media stream per session;
   - an input rate cap and a bounded ack window (~8 frames / 512 KiB);
   - the viewer sizes from `DecodedFrame`, never from `BindOk`;
   - release-all at session end;
   - `KeyframeRequest` on a decode error.
4. **GUI:** a manual winit loop + egui (`slice.md` §2), containing:
   - the ID and Tor status;
   - a connect field;
   - the client SAS confirm;
   - the **host consent popup (Allow / View-only / Deny)**;
   - a persistent **"screen is being shared with X" banner with Stop**;
   - the viewer, with keys by physical scancode.
5. **Windows build of the whole app.**
   - First fix the pre-existing Windows-only `clippy::result_large_err` in `tornect-core`: 88
     errors on gnullvm, because `GuardError`/`StoreError` are large there. The gate lints only
     the host target, so this has gone unnoticed.
   - Arti's ring, bundled SQLite and zstd on gnullvm are untested.
   - Try `CXXFLAGS_x86_64_pc_windows_gnullvm=-fstack-protector-strong` for OpenH264 (SLICE-A3 F4)
     and check that it links.
6. **`xtask pt-fetch` and `xtask dist`:**
   - `pt-fetch` implements `packaging/pt/SOURCES.md`: download, gpgv, member hash.
   - `dist` produces a Linux tarball and a Windows zip containing `lyrebird(.exe)`,
     `lyrebird.txt`, `THIRD_PARTY_NOTICES.md` and a README.
   - Pin toolchain hashes, and set `LZMA_API_STATIC=1` (SLICE-A3 F7).
7. **Security review of the slice diff.** Launch it as soon as the diff is frozen, and **ask the
   operator whether to run it at full size**: the refuted review is about 100 agents; this session
   ran A′ because that size was not approved. Then hand the operator the two packages with a test
   recipe.

### STILL OPEN / UNTESTED (do not mark these done)

- **Still open from the 2026-09-05 hand-off:**
  - the §B.8.15 A14 core-dump sweep;
  - the §B.8.5.2 per-minute and host-wide caps;
  - plan r7 (M1-31/M1-32);
  - the EFF word list;
  - `mlock`/`VirtualLock`;
  - the keyring canary;
  - `tests/integration` (missing);
  - the polkit policy install;
  - CI has never run.
- **Needs a device, or open:**
  - the fallback under real censorship;
  - onion-service hosting over bridges;
  - lyrebird's console behaviour on Windows;
  - polkit over SSH with `pkttyagent` (new row in `docs/VERIFICATION.md`).
- **Review items left for later:**
  - A1-8: `config show` and derived `Debug` print bridge lines.
  - A2-1: in-process OpenH264 decode of host-supplied video (sandbox at a later milestone).
  - F5: `multiple-versions = "deny"` policy.
  - F9/F10: read the Arti 0.46.0 and rustls 0.23.44/45 notes before tagging.
- **S9 residual:** zxcvbn still scores "Laptop-of-Ana tornect 2026" at 4, even with the label.
- **No capture, no session, no GUI yet: the app is not functional end to end.**

### GOTCHAS (new this session)

- **The gate now runs cargo-deny.** If `target/` is ever cleaned, `target/tools/` goes with it,
  and the step then says SKIPPED; restore the prebuilt binary (cargo-deny 0.20.2 musl).
- **Disk:**
  - The root disk was at 88–92 %. `target/debug/deps` is 36 G, and about 22 G of it had not been
    read in 3+ days (stale feature and toolchain variants).
  - Deleting artifacts by atime is **unsafe**: a missing proc-macro or low-level artifact makes
    cargo rebuild everything above it.
  - `~/.cache/tornect-probe*` (4.3 G of M0 probe target dirs) was deleted this session.
- **Per-package test runs rebuild.** `cargo test -p <crate>` can rebuild the tokio/rustls/Arti
  stack under a different feature unification (5–6 min); prefer `--workspace` or the gate.
- **Two gate failures that surfaced late:**
  - rustdoc fails on a public doc linking to a `pub` item of a private module unless it is
    re-exported (`tor::bridges::LYREBIRD_SHA256`).
  - The audit-log test used to flake on a 2-byte token match against random hash hex (fixed).

### PENDING USER ACTIONS

These are unchanged:
- Grant the `gh` token the `workflow` scope, then push CI.
- Create `.claude/settings.json`.
- Decide on the `framing` fuzz corpus.
- Arrange a second machine.
- Install the polkit policy.

New: decide whether `tornect host` should *refuse* Snowflake rather than warn (A1-7). Snowflake
volunteer proxies learn the host's IP, but refusing it breaks hosting where obfs4 is blocked.

Work autonomously per the CLAUDE.md ground rules. Commits carry **no AI references**. End the
session with this same kind of report plus memory, Part G and `docs/notes/m1-state.md` updates.

---

## What this session did

- Resumed at `efe75fa`.
- Ran the slice-range review first, as 3 read-only sub-agents on a frozen worktree, while fixing
  the track D findings in the main tree.
- Closed all 8 track D findings with failing-first regression tests, and checked them by hand
  under a real PTY and over the IPC socket.
- Synthesized the review and fixed its actionable findings:
  - private bridges replace the built-ins;
  - lyrebird is pinned and never taken from `PATH`;
  - the media bind key is HKDF-derived;
  - system power keys are refused;
  - cargo-deny is in the gate.
- Verified the obfs4 rung live with the pinned binary.

**Honest limits:**
- The app is **not yet functional end to end**: there is no capture, session layer or GUI, and
  `serve_host` is still not wired into `tornect host`.
- The whole Windows binary has not been built.
- `m1` is not tagged.
- CI has still never run.
- The slice review was the light A′ variant, without the adversarial refutation pass.
