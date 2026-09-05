# Tornect — continuation report (2026-09-04, session close)

Paste the block under **HAND-OFF** into a new session.

---

## HAND-OFF

Continue building Tornect from `/home/mx/Tornect` (private repo
https://github.com/Mxrider420z/Tornect, branch `main`, at `7630135`, tree clean,
**remote in sync — pushed 2026-09-04**).

Read in this order before doing anything: `CLAUDE.md`, `docs/notes/m1-state.md`,
`docs/PLAN.md` Part G, then `docs/PLAN.md` §B.3 and §B.8 (revision r6 + amendment
M1-37 — normative). Then run
`CARGO_BUILD_JOBS=3 TMPDIR=$PWD/target/tmp cargo xtask verify` to confirm green
(expect **289 tests**: 153 core + 136 signal).

### STATE (2026-09-04)

Commits this session, all pushed:
`5391f76` (log chain) → `7762849` (password test) → `3ee4943` (SAS fix) →
`43de8e0` (round-3 docs) → `08d391a` (OPAQUE core) → `324b4d4` (host branch) →
`fc48e24` (client branch + e2e) → `ba3cd7c` (track C docs) → `3d468f1` (track C
review fixes) → `7630135` (track C review docs).

- M0 done, tagged `m0`. **M1 ≈ two-thirds done, not tagged.**
- **M1 track 1** (`0e568d8`): Arti embedded, `tornect host` / `tornect ping` verified
  live over Tor.
- **M1 phase-2 part 1** (`cd878f3`): `tornect-core::unattended` + `tornect-signal`
  envelope/transcript/pairing/attended FSM.
- **Round-3 review of tracks A + B — done.** 12 hostile reviewers, 3 refuters per
  finding, 126 agents: **38 raw → 3 confirmed**, all fixed:
  - **HIGH, the SAS was grindable** (`3ee4943`, decision **M1-37**, supersedes M1-8).
    The r6 input `th_after(PAIR_REQUEST)` is attacker-malleable on both sides against a
    ~2^20 code. Reproduced: ~1500 candidates per side, collision at 323, both screens
    `034 057`, inside the 20 s `HELLO_ACK` timeout. §B.3 amended to commit-then-reveal
    (`HELLO.sas_commit`, `PAIR_REQUEST.sas_nonce`,
    `SAS = HKDF(th_after(HELLO_ACK) || sas_nonce)`). Both golden vectors and the
    envelope fuzz seeds regenerated; `client_random()` scripts a second value.
    **This partly answers M1-31**: signing `PAIR_REQUEST` alone would not have fixed
    it — the attacker re-signs each candidate with its own key.
  - MEDIUM: a `keystore_locked` window permanently broke the §B.8.13 log chain.
  - LOW: the file-keystore password escalation was never tested while VERIFICATION.md
    recorded U3 as VERIFIED.
- **Track C — done** (`08d391a`, `324b4d4`, `fc48e24`) and **reviewed** (`3d468f1`).
  OPAQUE-3DH authenticator + the §B.8.4.3 key schedule; the host `UnattendedHook` with
  the full §B.8.4.5 ordering, the write-ahead charge and the §B.8.5.2 budgets; the
  client branch with the `server_s_pk` TOFU pin. `fsm::tests::
  unattended_session_end_to_end_over_a_duplex_pipe` is a real `connect()` against a
  real `serve_host` running the real hook — no stub at any layer — reaching
  `SESSION_ACCEPT` with a derived token and zero popups (the B.8.14 M1 acceptance
  shape minus Tor).
  Its review (84 agents, **26 raw → 3 confirmed**) found and fixed: `export_key` /
  `session_key` dropped without zeroizing (opaque-ke's `*FinishResult` types are
  `derive_where(Clone)` only, **not** `ZeroizeOnDrop` — the doc comment claimed
  otherwise); pre-emption unimplemented, so `PREEMPTED` was emitted nowhere and the
  in-flight slot was held past `AwaitKe3`; and a missing `BYE{CLIENT_AUTH_ABORT}`.

### NEXT, in order

1. **Track D — CLI / IPC / platform.** `tornect pair|connect|unattended …|panic|devices`,
   the host-role IPC dispatch loop over the §B.8.7.4 message set, and the
   `tornect-platform` scaffold (`ipc`, `reauth`). **Carried in from track C** (its
   B.8.14 row, not delivered): **admin intent + scope** — the branch reaches
   `ADMIN_RESULT` but answers `ok: false, "not implemented at M1"`; the §B.8.4.1 scope
   rules (`unlock(pk)`, `suspend(pk ≠ self)`, `revoke(pk ≠ self)`, `revoke_all`) are
   unwritten — and the **stop token**, which `HELLO.stop_token` observes but the
   unattended path never consults.
   Cross-track notes still standing: the CLI must send `TOR_FALLBACK{}` after the
   accept (or set `orphan_timeout = None`) and use
   `fsm::HostAudit::new(Arc<SessionLog>)` as `HostDeps::audit`; `rotate-id`'s own
   `HostIdRotated` append must stop once wired to the guard. Also wire
   `ServerKeyPin` to a real `hosts.toml` (the headless default trusts on first use and
   remembers nothing) and `OpaqueServerSetupSource` into the guard.
2. **Track E — adversarial + fuzz sweep** → `security-reviewer` milestone close →
   **live verification** (pair + attended + unattended over real Tor, two
   `TORNECT_HOME` instances) → tag `m1`.
3. Then **u1** (UI plan U0+U1), then M2.

### STILL OPEN / UNTESTED (do not mark these done)

- The §B.8.15 **A14 core-dump sweep** is OPEN. The new wipe test covers the primitive
  and the observable contract only — once `finish()` returns its frame is gone and no
  safe-Rust test can inspect it. Marked partial in VERIFICATION.md deliberately.
- §B.8.5.2's **per-minute and host-wide caps have no dedicated test**; only the per-pk
  slot lifetime and pre-emption do.
- Deferred to plan **r7** (decisions M1-31 / M1-32): whether `PAIR_REQUEST` /
  `PAIR_ACCEPT` are signed (M1-37 answers half of this), and whether `quic_spki` binds
  the pairing-pinned `host_device_pk` instead of the onion identity key.
- OPEN rows worth knowing: EFF passphrase word list (M8), `mlock`/`VirtualLock` (M6),
  keyring canary + persistent OS backends (M6), grant preconditions reading
  unauthenticated inputs.

### GOTCHAS

- Always `CARGO_BUILD_JOBS=3 TMPDIR=$PWD/target/tmp` (`/tmp` is a 3.7 GiB quota tmpfs);
  Tor state under `target/tornect-test/`, never `/tmp`. Docs-only commits:
  `TORNECT_SKIP_HOOKS=1`.
- **Disk:** the tree hit 47 G on a 99 G root at 97% full this session and was cleaned to
  19 G. Safe to delete: `target/debug/incremental`, `fuzz/target`, `target/<track>` dirs,
  `target/doc`, cross-compile dirs, stale `*.log`. **Keep** `target/debug/deps` (18 G —
  else a cold Arti rebuild) and `target/tornect-test/` (10 real Ed25519 seeds + a live
  onion service).
- **Workflow concurrency is 2**, not "as many as you launch" — `mx-vm` has 4 vCPU. A
  126-agent review took 4h26m, an 84-agent one 2h50m. Launch them in the background,
  never near the end of a session; a usage-limit death loses the whole run.
- If a worktree ever shares `target/`, `target/debug/xtask` embeds *that* worktree's
  root and `cargo xtask verify` silently verifies the wrong tree — `touch
  xtask/src/main.rs` first, or give it its own `CARGO_TARGET_DIR`.
- **Test-harness facts** (cost time to rediscover): a grant needs
  `MutationGuard::master_on` (the switch is off by default, §B.8 opt-in) and
  `Preset::HeadlessBox` (the one preset that waives the "prior attended session"
  precondition); the OPAQUE registration must run against the `ServerSetup` the store
  ends up holding, so bootstrap first and read `server_setup()` back.
- Piping cargo through `grep`/`tail` masks its exit code — the pipeline's status is the
  last command's. Redirect to a file and check `$?`.

### PENDING USER ACTIONS

1. `gh auth refresh -h github.com -s workflow`, then
   `git add -f .github/workflows/ci.yml && git commit -m "ci: add GitHub Actions workflow" && git push`
   (token lacks the `workflow` scope; file excluded via `.git/info/exclude`).
   **CI has still never run.**
2. Copy `.claude/settings.recommended.json` to `.claude/settings.json` after review.
3. Decide whether to commit the **`framing` fuzz corpus**: `framing` is a live fuzz
   target but its corpus exists only in the gitignored `target/fuzz-corpus/framing`,
   one `cargo clean` from gone. It belongs in `fuzz/corpus/framing/`.
4. A second machine would clear the "two machines on different NATs" NEEDS-DEVICE rows.

Work autonomously per the CLAUDE.md ground rules (verify like hostile QA, never start
M(n+1) with M(n) red, `security-reviewer` at milestone close). Commits carry **no AI
references**. End the session with this same kind of report plus memory, Part G and
`docs/notes/m1-state.md` updates.

---

## What this session did

Cleaned the tree from 47 G to 19 G (the disk was at 97%, one build from failing); ran a
12-dimension hostile review of the unreviewed tracks A/B and fixed all three survivors,
including a HIGH protocol flaw that made the pairing SAS provide no MITM protection at
all — reproduced, then fixed with a normative §B.3 amendment; built track C end to end
(OPAQUE-3DH core, host branch, client branch, headless end-to-end session); reviewed it
and fixed all three survivors there too. Gate green at 289 tests throughout; 10 commits
pushed.

**Honest limits:** `m1` is not tagged; track D and track E are untouched; admin intent
+ scope and the stop token from track C's own B.8.14 row are stubbed, not done; live
verification over real Tor has not run since track 1; the A14 core-dump sweep and the
§B.8.5.2 rate caps remain untested; and CI has still never run on GitHub.
