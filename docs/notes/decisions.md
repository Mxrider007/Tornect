# Decision log

Format follows `docs/PLAN.md` §A.3. Newest at the bottom. Decisions that change the
plan's text are also applied to `docs/PLAN.md` (and `TORNECT_PLAN.md`, kept identical).

| # | Date | Decision | Choice | Why | Rejected alternatives |
|---|---|---|---|---|---|
| M0-1 | 2026-08-28 | License (Part F.1) | GPL-3.0-or-later | Plan recommendation; Sunshine-compatible; blocks proprietary forks | MIT/Apache (no copyleft), AGPL (no network-service angle here) |
| M0-2 | 2026-08-28 | Primary dev OS (Part F.2) | Linux/Wayland — GNOME on Ubuntu 26.04 (the build VM) | It is the machine Claude Code runs on and the trickiest stack, as the plan recommends | — |
| M0-3 | 2026-08-28 | Unattended access (Part F.3) | In v1, opt-in per device, per §B.8 | User request; protocol pieces land in M1, gating in M4, UI in M8 | Post-v1 |
| M0-4 | 2026-08-28 | Minimum targets (Part F.4) | Windows 10 20H1+, macOS 13+, xdg-desktop-portal ≥ 1.17 | Confirmed as proposed | — |
| M0-5 | 2026-08-28 | Software codec fallback | `openh264` (Cisco, BSD) built from vendored source via `cc`, always compiled in | Runs on any machine and in CI without system libs (the dev VM has no FFmpeg headers and no sudo); H.264 baseline is fast enough for a 1080p loopback demo on 4 cores | FFmpeg-only (needs libav* + libclang at build time); `rav1e` (too slow at 1080p60 on CPU, no matching pure-Rust decoder) |
| M0-6 | 2026-08-28 | Where hardware codecs live | `tornect-codec/ffmpeg` feature (libavcodec hw contexts) verified in Linux CI | Plan D8 unchanged; feature-gating is what makes the workspace buildable everywhere | Building FFmpeg from source in the VM (needs libclang headers for bindgen anyway) |
| M0-7 | 2026-08-28 | Claude Code permission/hook config | Committed as `.claude/settings.recommended.json`; git `pre-commit` hook enforces fmt + clippy | The harness refuses to let the model write its own `settings.json`; the git hook gives the same gate to humans and agents | Skipping the gate |
| M0-8 | 2026-08-28 | Plan file location | `TORNECT_PLAN.md` (repo root, the user's file) and `docs/PLAN.md` (plan-mandated path) kept byte-identical; `cargo xtask verify` fails if they drift | Both locations are expected by different readers | Symlink (breaks on Windows checkouts) |
| M0-9 | 2026-08-28 | Onion-service identity key | Tornect owns the ed25519 seed (file keystore) and shows the ID at M0; at M1 the same seed is handed to Arti (expanded-key derivation) so the address never changes | Plan D3: "onion address = host identity"; lets `tornect id` work before Tor is even bootstrapped | Letting Arti generate the key in its own keystore (ID would be unknown until first bootstrap) |
| M0-10 | 2026-08-28 | GitHub transport | HTTPS remote with the `gh` credential helper | SSH key in `~/.ssh/config` is not usable non-interactively on this VM | SSH |
