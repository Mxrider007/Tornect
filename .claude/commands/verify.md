---
description: Run the full Tornect verification gate (fmt, clippy -D warnings, tests, doc-tests, per-crate extras) and the milestone demo for the current crate
---
Run the Tornect verification gate and report results honestly (§D.1 rule 3, §D.5):

1. `cargo xtask verify` (fmt check → clippy -D warnings on all targets → tests → doc tests → per-crate extras). If `$ARGUMENTS` names a crate, additionally run `cargo test -p $ARGUMENTS -- --nocapture` and that crate's runtime demo:
   - `tornect-core`: `cargo run -p tornect -- id` prints a valid 56-char onion ID and `tornect doctor` reports all paths.
   - `tornect-signal`: `cargo run -p tornect -- host --once` in one process and `cargo run -p tornect -- ping <onion>` in another (see docs/VERIFICATION.md for the two-instance TORNECT_HOME recipe).
   - `tornect-net`: `cargo test -p tornect-net --features harness` plus `tests/netem/run.sh lan` if netns is available (needs root; otherwise record NEEDS-DEVICE).
   - `tornect-proto` / `tornect-codec` / `tornect-capture`: `cargo run -p tornect -- demo --loopback --headless-stats --seconds 60` and read the printed HUD stats against docs/PLAN.md §B.7.
2. Paste the actual command output summary (pass/fail counts, timings, any warnings) into the reply. Do not summarize a failure as a pass.
3. Update `docs/VERIFICATION.md` rows that changed status (VERIFIED with machine + date, or NEEDS-DEVICE).
