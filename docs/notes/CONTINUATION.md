# Tornect — continuation report (2026-09-21, session close)

Paste the block under **HAND-OFF** into a new session.

---

## HAND-OFF

Continue building Tornect from `/home/mx/Tornect` (private repo
https://github.com/Mxrider420z/Tornect, branch `main`, pushed). The operator's goal for this
run: **a functional app on Linux and Windows** (the operator will test with one Linux and one
Windows machine), **Tor with automatic obfs4 bridges when Tor is blocked and Snowflake when
obfs4 fails**, and **the code cross-compiling for Windows**. Scope ruling (operator,
2026-09-21): **"vertical slice first"** — a real Linux↔Windows remote session end to end
(Tor transport, software H.264, one capture + input backend per OS, minimal egui window with
the consent popup, sharing indicator and kill switch, cross-built Windows binary, packaged
zips); QUIC hole punching deferred; m2–m6 stay untagged until their full acceptance runs.

Read in this order before doing anything: `CLAUDE.md`, this file, `docs/notes/m1-state.md`
(§ *Session 2026-09-21*), `docs/research/bridges.md`, `docs/research/slice.md`,
`docs/notes/decisions.md` M1-38 / M1-39 / M3-1, and the track D review
`/home/mx/kore_project_V3/agents/security/reports/2026-09-21_tornect_track_d_review.md`.
Then run `CARGO_BUILD_JOBS=3 TMPDIR=$PWD/target/tmp cargo xtask verify` (expect **344 tests**:
329 before this session's slice crates + 5 proto + 7 input + 3 codec).

### STATE (2026-09-21)

Commits this session, pushed: `213e7d9` (the bridge ladder) → the slice-crates commit
(`tornect-proto`, `tornect-input`, `tornect-codec`, Windows cross-build config, docs).

1. **Bridges — done and live-verified (M1-38).** `tor.bridges = auto` (default) tries direct
   Tor, then Tor Browser's 7 built-in obfs4 bridges, then its 2 Snowflake lines, each rung a
   fresh Arti client on its own runtime (teardown releases the state lock — a bridged client
   that cannot take it fails for good), success only on `ready_for_traffic`, last good rung
   remembered in `state/tor-transport`. `--bridges off|obfs4|snowflake` forces a rung;
   `tor.bridge_lines` adds private bridges; `tornect tor-check` / `tornect doctor` report.
   **One binary, lyrebird 0.8.1, serves obfs4 and Snowflake** (there is no separate
   snowflake-client any more). Fetched from the GPG-verified tor-expert-bundle 15.0.23, pins
   in `packaging/pt/SOURCES.md`, extracted (not committed) to `target/pt/{linux,windows}-x86_64/
   tor/pluggable_transports/`. Live, cold cache: direct 14.3 s, obfs4 78.2 s, Snowflake 16.2 s.
2. **Media port (M1-39).** The onion service accepts `BEGIN` on 4000 (signaling) and **4001
   (`MEDIA_PORT`)** only; `OnionStream::port()`; `TorNode::connect_on(id, port, &Isolation)`
   opens the media stream on the signaling stream's rendezvous circuit. `tornect host` (still
   the ping loop) closes 4001 streams. The bind is designed (`tornect-proto`): first client
   frame `Bind{session_id, HMAC-SHA256(session_token, "tornect/v1/tor-media-bind\0" ‖ th_final)}`,
   checked in constant time before anything is captured.
3. **Slice crates written and tested:** `tornect-proto` (media framing: Bind/BindOk/Video/
   VideoAck/Input/KeyframeRequest/Ping/Pong/Close, `read_msg`/`write_msg`, `bind_mac`),
   `tornect-input` (16-byte event, USB-HID key table generated from Chromium's
   `dom_code_data.inc` — BSD notice kept, `THIRD_PARTY_NOTICES.md` — `Tracked` release-all
   wrapper, XTEST and `SendInput` injectors), `tornect-codec` (OpenH264 from source, BT.601,
   even-size crop, forced IDR).
4. **Windows cross-build route works.** llvm-mingw **20260908** in
   `~/.local/opt/llvm-mingw-20260908-ucrt-ubuntu-22.04-x86_64` (checksum-verified), Rust
   target `x86_64-pc-windows-gnullvm` (installed, now in `rust-toolchain.toml`),
   `.cargo/config.toml`: `+crt-static` + `CXXSTDLIB_x86_64_pc_windows_gnullvm=c++`.
   `cargo build --target x86_64-pc-windows-gnullvm -p tornect-codec` links OpenH264's C++.
   Put `…/llvm-mingw-…/bin` on `PATH` first.
5. **Track D review — it actually ran this time** (105/105 agents, 44 min, launched first
   against a frozen worktree `/home/mx/tornect-review-trackd` @ `7697823`). 33 raw → 12
   survivors → **8 distinct**. Only S1 was re-verified by hand so far; **none is fixed yet**.

### NEXT, in order

1. **Fix the track D survivors** (verify each against the code first — the review's own rule;
   the report has scenarios and suggested fixes):
   - **S1 HIGH (verified by hand):** `tornect-platform/src/ipc.rs:298` — `request()` reads the
     answer under the 30 s `IDLE_TIMEOUT`, but the host's handler runs the polkit dialog for up
     to 120 s (`reauth.rs:143`), so `unattended on` can commit *after* the CLI reported failure
     and its one-time stop code is lost. Fix: a response timeout ≥ dialog timeout + margin (or
     an interim "awaiting re-auth" frame), and on the host roll back an `On` whose answer
     cannot be delivered (`master_off` is deny-direction, needs no re-auth).
   - S2 MEDIUM `fsm/host.rs:638` — `apply_admin_effect` is skipped when the `ADMIN_RESULT`
     write fails although the store change committed: apply the effect regardless, then
     propagate the send error.
   - S3/S10 `signal/src/unattended.rs:216` + core `guard.rs` — a failed *post-commit*
     `log_event` makes `MasterOff`/`RevokeAll`/`Revoke` report failure and drop the kill:
     make those log writes best-effort (warn) so a committed mutation returns `Ok` + effect.
   - S5 MEDIUM `apps/tornect/src/unattended.rs:552` — the offline CLI opens the store in
     `LoadMode::Host` (settles/decays/persists `FailState`; M1-24 says the offline CLI never
     does): use `GrantStore::open_offline` on the offline route.
   - S6 MEDIUM `ipc.rs:244` — the serial endpoint makes `off`/`panic`/`revoke`/`suspend` wait
     behind a pending re-auth dialog: serve connections concurrently and serialize only
     store mutations, or let deny-direction ops bypass the queue.
   - S7 LOW `packaging/polkit/org.tornect.policy:44` — `allow_any=no`/`allow_inactive=no`
     vs §B.8.8 "text agent over SSH": decide (the plan text or the policy) and align.
   - S8/S12 LOW — password/stop-code bytes left in std's stdin buffer and `String` reallocs:
     read into a `Zeroizing` buffer via rustix directly.
   - S9/S11 LOW `unattended.rs:577` — zxcvbn `user_inputs` omit device labels; whitespace
     and waiver warnings dropped: pass labels, surface the warnings.
2. **Wire `serve_host` into `tornect host`** (critical path since 2026-09-05): the seams in the
   previous hand-off (`HostDeps::unattended`, `stop_token`, `audit`, `trusted`, `consent` = a
   CLI/GUI prompt, **`kill` shared with the IPC `HostContext`**), plus a new `SessionSink`
   seam called right after `SESSION_ACCEPT` is sent (session id, token, `th_final`, mode,
   label) so the media server can verify binds, and on session end. Client: `connect` →
   `send_tor_fallback` → `connect_on(MEDIA_PORT, same Isolation)` → `Bind`; keep the signaling
   stream alive with `PING`s (host idle timeout 90 s).
3. **`tornect-capture`**: `VideoSource` trait (blocking `next_frame`, tight BGRx); synthetic
   test card; X11 (`XDG_SESSION_TYPE=x11`: GetImage + XFIXES cursor); **Wayland: one
   RemoteDesktop portal session with ScreenCast sources** (`ashpd`), PipeWire via **dlopen** —
   struct layouts and the exact 232-byte EnumFormat pod in `docs/research/slice.md` §4 and the
   full report §4.3/§4.6 (Mutter offers only BGRx/BGRA and framerate 0/1; read size from the
   negotiated Format; always requeue buffers); the portal session also yields the input sink
   (`Notify*`, never `connect_to_eis`); Windows GDI (`BitBlt` from the virtual screen).
4. **`tornect-session`**: host media server on `MEDIA_PORT` (bind → capture → encode → `Video`
   with an ack window of ~8 frames / 512 KiB so latency stays bounded; `Input` reaches a
   `Tracked` injector **only when mode = CONTROL**; release-all on end); viewer (decode →
   frames to the UI; `KeyframeRequest` on decode error; acks).
5. **GUI** in `apps/tornect` (manual winit loop + egui, `docs/research/slice.md` §2): ID +
   Tor status (ladder events), connect field, client SAS confirm, **host consent popup
   (Allow / View-only / Deny)**, **persistent "screen is being shared with X" banner with
   Stop**, viewer with a native wgpu texture, keys forwarded by physical scancode
   (`to_scancode` → `keymap::by_evdev/by_win` → USB usage).
6. **Windows build of the whole app** (Arti's ring / bundled sqlite / zstd on gnullvm are
   untested), then **`xtask dist`**: Linux tarball + Windows zip with `lyrebird(.exe)`,
   `lyrebird.txt`, `THIRD_PARTY_NOTICES.md`, README; `xtask pt-fetch` implementing
   `packaging/pt/SOURCES.md`.
7. **Security review of the slice diff — launch it as early as the diff is frozen** (the
   usage-limit lesson), then hand the operator the two packages with a test recipe.

### STILL OPEN / UNTESTED (do not mark these done)

- Everything the 2026-09-05 hand-off listed: §B.8.15 A14 core-dump sweep, §B.8.5.2 per-minute
  and host-wide caps, plan r7 (M1-31/M1-32), EFF word list (M8), `mlock`/`VirtualLock` (M6),
  keyring canary (M6), `tests/integration` (missing), the polkit policy install, CI never run.
- The automatic fallback under **real** censorship (NEEDS-DEVICE), onion-service hosting over
  bridges (OPEN), lyrebird console behaviour on Windows (NEEDS-DEVICE) — `docs/VERIFICATION.md`.
- No capture, no session, no GUI yet: **the app is not functional end to end.**

### GOTCHAS (new this session)

- Dev runs need `TORNECT_PT_DIR=$PWD/target/pt/linux-x86_64/tor/pluggable_transports` (or
  `tor.pt_path`); without lyrebird the ladder is direct-only and says so.
- Windows builds: `export PATH=$HOME/.local/opt/llvm-mingw-20260908-ucrt-ubuntu-22.04-x86_64/bin:$PATH`.
- Do not put licence text in `//!` doc comments — clippy's `doc_lazy_continuation` fails the
  gate on the indented list; plain `//` comments are fine.
- The frozen review worktree `/home/mx/tornect-review-trackd` is still registered
  (`git worktree list`); remove it with `git worktree remove` once the survivors are fixed.
- Disk: 17 G free at close (83 %); a Windows `target/x86_64-pc-windows-gnullvm` tree will add
  several GB — clean `target/debug/incremental` first if needed.

### PENDING USER ACTIONS

Unchanged from the previous hand-off (CI has never run; `.claude/settings.json`; the `framing`
fuzz corpus; a second machine; the polkit policy install).

Work autonomously per the CLAUDE.md ground rules. Commits carry **no AI references**. End the
session with this same kind of report plus memory, Part G and `docs/notes/m1-state.md` updates.

---

## What this session did

Resumed from `7697823`. Re-ran the track D hostile review first, against a frozen worktree —
it completed (105/105 agents) with 12 surviving findings, one HIGH verified by hand. Built the
censorship-circumvention ladder (direct → obfs4 → Snowflake) on a fresh Arti client per rung,
with Tor Browser's built-in bridges and the Tor Project's signed lyrebird, and verified all
three rungs live. Added the media port and the same-circuit connect. Wrote and tested the
media wire protocol, the input event + USB key table + injectors, and the OpenH264 codec, and
proved the Windows cross-build route by linking OpenH264's C++ for `x86_64-pc-windows-gnullvm`.

**Honest limits:** the app is **not yet functional end to end** — no capture, session layer or
GUI; `serve_host` is still not wired into `tornect host`; the track D survivors are **unfixed**;
the full Windows binary has not been built; `m1` is not tagged; CI has still never run.
