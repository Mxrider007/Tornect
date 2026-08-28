---
description: Execute Tornect milestone $ARGUMENTS end-to-end (plan → implement → verify → tag) per docs/PLAN.md Part C/D
---
We are executing **Milestone $ARGUMENTS** of Tornect.

1. Read `CLAUDE.md`, then `docs/PLAN.md` Part C entry **M$ARGUMENTS** and every §A/§B section it references (follow the cross-references; for anything touching pairing, consent or unattended access also read §B.6 and §B.8). Read `docs/VERIFICATION.md`, `docs/DEPENDENCIES.md`, and the newest `docs/notes/m*-state.md` if present.
2. Confirm the previous milestone is green: `git tag --list 'm*'` shows `m$(($ARGUMENTS-1))` and `cargo xtask verify` passes on `main`. If not, stop and report — never start M(n+1) with M(n) red (§D.1 rule 1).
3. Enter plan mode. Produce the task DAG for this milestone: tasks, owning subagent from `.claude/agents/`, dependencies, and which tracks can run in parallel per §D.4 (use `git worktree add ../tornect-<track> m$ARGUMENTS-<track>` for parallel implementation tracks). Include the research-verifier fan-out for any new dependency or OS API. Get sign-off, then exit plan mode.
4. Implement. Every task ends with the gate: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, plus the milestone's runtime demo (§D.1 rule 3). Run things; do not assume. Record any new dependency in `docs/DEPENDENCIES.md` with version, rationale and verified-on date.
5. Run the milestone's **Accept** criteria from Part C literally. Anything that needs hardware or an OS you cannot run goes into `docs/VERIFICATION.md` as `NEEDS-DEVICE(<os>)` with exact reproduction steps.
6. Invoke the `security-reviewer` agent on the milestone diff (mandatory for signal/net/pairing/consent/unattended changes); findings become blocking tasks.
7. Write `docs/notes/m$ARGUMENTS-state.md` (done / next / gotchas), commit with conventional commits, tag `m$ARGUMENTS`, push, and print the kickoff prompt for the next milestone.
