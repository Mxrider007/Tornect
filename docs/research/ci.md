# Toolchain & CI — sourced research note (verified 2026-08-28)

Scope: GitHub Actions action versions, runner images, apt package versions on the
runner images, billing limits for a **private** repo on the free plan, cargo-fuzz /
nextest / cargo-deny tooling, Rust edition 2024, the xtask alias, and cross-`cargo check`
feasibility for the Windows (`windows` crate) and macOS (`objc2` family) platform code.
Every claim cites a URL, a `gh api` call, or a path under `/tmp/crates-src/<crate>`.
Repo facts: `Mxrider420z/Tornect` is **private** (`gh api repos/Mxrider420z/Tornect` →
`private=true`), default branch `main`.

## 0. What was actually verified on this VM (the build VM, Rust 1.96.0 stable)

| Probe | Where | Result |
|---|---|---|
| `cargo check --target x86_64-pc-windows-msvc` on a crate using `windows = "=0.62.2"` with WGC + D3D11 + SendInput + WASAPI features (§8.1) | `/tmp/probe-win-cross` (target dir `~/.cache/tornect-probes/target-win`) | **green** — `Finished dev profile … in 5.57s` after 9 s cold; no Windows linker needed for `check`. Two API mistakes found and fixed in the process (§8.1 gotchas) |
| `cargo check --target aarch64-apple-darwin` on a crate using `objc2 =0.6.4`, `objc2-screen-capture-kit =0.3.2`, `objc2-core-graphics =0.3.2` (CGEvent), `objc2-core-media`, `block2 0.6`, `dispatch2 0.3` (§8.2) | `/tmp/probe-mac-cross` (target dir `~/.cache/tornect-probes/target-mac`) | **green** — `Finished dev profile` (4.8 s cold). One API mistake fixed (`NSArray::iter` needs the `NSEnumerator` feature; used `firstObject()`) |
| `rustup target list --installed` | VM | `aarch64-apple-darwin`, `x86_64-pc-windows-msvc`, `x86_64-unknown-linux-gnu` already installed (added during M0); `rustup toolchain list` = stable 1.96.0 + 1.92.0 (no nightly) |
| `cargo install cargo-fuzz --version 0.13.2 --locked` on stable | `~/.cargo/bin/cargo-fuzz` | **builds & installs on stable** (cargo-fuzz itself is a normal stable crate) |
| `cargo fuzz build -s none` + `cargo fuzz run -s none fuzz_target_1 -- -runs=2000` with **stable 1.96** | `/tmp/probe-fuzz-stable` | **works**: `Finished release profile … 18.61s`, `#2000 DONE cov: 12 ft: 13 … Done 2000 runs`. The sancov instrumentation flags cargo-fuzz passes are all `-C` (stable) flags |
| `cargo fuzz build` (default = AddressSanitizer) with stable 1.96 | same | **fails**: `error: 1 nightly option were parsed` — the command line contains `-Zsanitizer=address`. ASan fuzzing needs nightly (§6) |
| `cargo deny check licenses bans sources advisories` with the prebuilt cargo-deny **0.20.2** musl binary | scratchpad `bin/cargo-deny` run in the repo | runs fine against `deny.toml` (`version = 2` accepted); **licenses FAILED** (3 crates), **advisories FAILED** (2 advisories), bans = warnings only, sources ok — see §7.3 for the exact fixes |
| `cargo nextest run --workspace --no-fail-fast` with the prebuilt cargo-nextest **0.9.143** binary (get.nexte.st tarball) | repo | `Summary [0.068s] 47 tests run: 47 passed, 1 skipped` (44 s wall incl. test-binary build) |
| Rust channel manifests (`static.rust-lang.org/dist/channel-rust-*.toml`) | — | stable = **1.98.0 (88d9e12ae 2026-08-18)**, beta = 1.99.0-beta.1, nightly = **1.100.0-nightly (e457a7b0d 2026-08-27)**, channel date 2026-08-28. This VM is two stable releases behind (1.96.0, 2026-05-25) — `rustup update` before chasing clippy differences vs CI |

Gotcha hit while probing: `/tmp` on this VM is a **3.7 GiB tmpfs**; putting a probe's
`target/` under `/tmp` filled it (the `windows` crate alone extracts to 111 MB and its
check artifacts ~84 MB) and every shell command started failing with exit 1 until space
was freed. Keep `CARGO_TARGET_DIR` and `TMPDIR` under `$HOME` for probes
(`~/.cache/tornect-probes/…`), as `docs/DEPENDENCIES.md` already warns for `TMPDIR`.

## 1. GitHub Actions — recommended pins

All latest tags resolved with `gh api repos/<owner>/<repo>/releases/latest` and
`…/tags`, runtimes read from each tag's `action.yml` (`gh api repos/<r>/contents/action.yml?ref=<tag>`),
full SHAs from `gh api repos/<r>/commits/<tag>` on 2026-08-28.

| Action | Latest release | Floating major tag to use | Runtime (`runs.using`) | Full SHA of the latest release (for `@<sha> # vX.Y.Z` pinning) |
|---|---|---|---|---|
| `actions/checkout` | **v7.0.1** (2026-07-20) | `@v7` | `node24` | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| `actions/upload-artifact` | **v7.0.1** (2026-04-10) | `@v7` | `node24` | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` |
| `actions/download-artifact` | **v8.0.1** (2026-03-11) | `@v8` | `node24` | `3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c` |
| `actions/cache` | **v6.1.0** (2026-06-26) | `@v6` | `node24` | `55cc8345863c7cc4c66a329aec7e433d2d1c52a9` |
| `dtolnay/rust-toolchain` | no releases; **branches** `stable`, `nightly`, `master`, `1.42`…`1.0`; single tag `v1` | `@stable` / `@nightly` / `@master` (see §1.1) | `composite` | `stable` = `4360b52568e2003a75bf9bc1d59f33a8e3fc893c`, `master` = `6c977a6ca4077a0ceb28ffbe03f59d46e9ac8772`, `nightly` = `7c8d7d138f5c09cef361f8214cf96882cd029cdb` (all 2026-08-05) |
| `Swatinem/rust-cache` | **v2.9.2** (2026-08-06) | `@v2` | `node24` (migrated in 2.9.0, PR #314) | `6323deb102c322ba6fcbdcafc7e3dddab59af2b6` |
| `taiki-e/install-action` | **v2.87.0** (2026-08-27; releases almost daily) | `@v2`, or the per-tool tags `@cargo-nextest`, `@nextest`, `@cargo-deny`, `@cargo-audit` (verified to exist via `git/ref/tags/<name>`); **no `@cargo-fuzz` tag and no `manifests/cargo-fuzz.json`** | `composite` (bash+jq+curl) | `37f7c5781271959fb65b6b35224e28652ff2b63d` |
| `softprops/action-gh-release` | **v3.0.2** (2026-07-13) | `@v3` | `node24` (v3.0.0: "moves the action runtime from Node 20 to Node 24 … stay on `v2.6.2`" for Node 20) | `3d0d9888cb7fd7b750713d6e236d1fcb99157228` |
| `EmbarkStudios/cargo-deny-action` | **v2.1.1** (2026-07-13) | `@v2` | `docker` (`Dockerfile`: `FROM rust:1.85.0-alpine3.20`, downloads **cargo-deny 0.20.2** musl tarball) | `3c6349835b2b7b196a839186cb8b78e02f7b5f25` |
| `rustsec/audit-check` | v2.0.0 (**2024-09-23**, still `node20`) | **do not use** (§1.2) | `node20` | — |
| `actions-rust-lang/audit` | v1.2.7 (2026-01-05) | `@v1` if a cargo-audit job is wanted | `composite` (`cargo +stable install cargo-audit --vers 0.22.0`, cached) | `72c09e02f132669d52284a3323acdb503cfc1a24` |

### 1.1 `dtolnay/rust-toolchain` scheme (README + `action.yml@master`)

- "The selection of Rust toolchain is made based on the particular @rev of this Action
  being requested. For example `dtolnay/rust-toolchain@nightly` pulls in the nightly Rust
  toolchain, while `dtolnay/rust-toolchain@1.89.0` pulls in 1.89.0." Branches exist for
  every `1.N` / `1.N.M` up to `1.42` … plus `stable`, `beta`, `nightly`, `master`
  (`gh api repos/dtolnay/rust-toolchain/branches`). The only tag is `v1`.
- "When passing an explicit `toolchain` as an input instead of @rev, you'll want to use
  `dtolnay/rust-toolchain@master` as the revision of the action." So a **pinned nightly**
  is `uses: dtolnay/rust-toolchain@master` + `with: { toolchain: nightly-2026-08-28 }`.
- Inputs (`action.yml`): `toolchain` (required — "GitHub does not enforce `required: true`
  inputs itself"), `targets` (comma-separated), `target` (alias), `components`
  (comma-separated). Outputs: `cachekey` ("short hash of the rustc version"), `name`
  (rustup name, "suitable for use with `cargo +${{steps.toolchain.outputs.name}}`").
- Expressions supported: `stable 18 months ago`, `stable minus 8 releases`, `1.N`.
- README usage (verbatim): `- uses: actions/checkout@v7` / `- uses: dtolnay/rust-toolchain@stable` /
  `- run: cargo test --all-features`. Source: https://github.com/dtolnay/rust-toolchain

### 1.2 Node 20 removal — the hard deadline that affects our current `ci.yml`

GitHub changelog (https://github.blog/changelog/2025-09-19-deprecation-of-node-20-on-github-actions-runners/,
with editor's notes of 2026-02-25, 2026-05-19 and **2026-08-25**): runners "will begin using
Node24 by default" on **June 16, 2026**, and Node 20 is **removed from the runner on
September 23, 2026** (date moved by the 2026-08-25 note). Opt-outs:
`FORCE_JAVASCRIPT_ACTIONS_TO_NODE24=true` (test early) /
`ACTIONS_ALLOW_USE_UNSECURE_NODE_VERSION=true` (keep Node 20 until removal only).

Consequences (verified with `action.yml?ref=<tag>`):
- `actions/checkout@v4` is `node20` → **must move to `@v7`** (v5 and v6 are already
  `node24`; v6 changed credential persistence — "Persist creds to a separate file"; v7
  "block checking out fork pr for pull_request_target and workflow_run" + ESM).
- `actions/upload-artifact@v4` is `node20` → use `@v7`; pair with `download-artifact@v8`
  (v8: "Hash mismatches will now error by default" via `digest-mismatch`; "will no longer
  attempt to unzip all downloaded files"; `skip-decompress` input).
- `rustsec/audit-check@v2` is `node20` and last released 2024-09 → replace with
  `cargo deny check advisories` (already covers RustSec) or `actions-rust-lang/audit@v1`.
- `actions/cache@v6` requires "minimum Actions Runner version of `2.327.1`" (v5 notes;
  v6 = ESM migration) — irrelevant for GitHub-hosted runners, matters for self-hosted.

### 1.3 `Swatinem/rust-cache@v2` — inputs that matter (from `action.yml@v2`)

`prefix-key` (default `v0-rust`), `shared-key` (stable across jobs), `key`,
`add-job-id-key` (default true), `add-rust-environment-hash-key` (default true — hashes
`Cargo.toml`/`Cargo.lock`/`rust-toolchain`/`.cargo/config.toml` + `env-vars`), `env-vars`,
`workspaces` (`$workspace -> $target` lines), `cache-directories`, `cache-targets`
(default true), `cache-on-failure`, `cache-all-crates`, `cache-workspace-crates` (2.8.0),
`save-if` (default true), `cache-provider` (`github`|`warpbuild`), `cache-bin` (default
true — caches `~/.cargo/bin`, i.e. tools installed by install-action are cached too),
`lookup-only`, `cmd-format`; output `cache-hit`. README rule: "selecting a toolchain either
by action or manual `rustup` calls should happen before the plugin, as the cache uses the
current rustc version as its cache key". 2.9.0 added "Consider all installed toolchains in
cache key" (PR #293). Source: https://github.com/Swatinem/rust-cache

### 1.4 `taiki-e/install-action` (README + `manifests/` listing)

- Usage: `uses: taiki-e/install-action@v2` with `tool: cargo-nextest` (or several,
  comma/space separated). Version pinning: `tool: cargo-hack@0.5.24` / `@0.5`
  (series); shorthand `uses: taiki-e/install-action@cargo-hack`.
- Manifests present for our tools (`gh api repos/taiki-e/install-action/contents/manifests`):
  `cargo-nextest.json` (latest **0.9.143**), `cargo-deny.json` (**0.20.2**),
  `cargo-audit.json` (**0.22.2**), `cargo-hack.json`, `cargo-llvm-cov.json`,
  `cargo-binstall.json` (**1.22.0**), `cargo-machete.json`, `cargo-udeps.json`,
  `cargo-semver-checks.json`, `zizmor.json`, `typos.json`, `taplo.json`, `just.json`, `sccache.json`.
  **No `cargo-fuzz.json`** → the README's fallback applies: unsupported tools go through
  `cargo-binstall` (`fallback: none` disables it). cargo-fuzz 0.13.2 ships GitHub release
  assets `cargo-fuzz-0.13.2-x86_64-unknown-linux-musl.tar.gz` / `-x86_64-apple-darwin.tar.gz`
  / `-x86_64-pc-windows-msvc.zip` (`gh api repos/rust-fuzz/cargo-fuzz/releases/latest`),
  so binstall should find a binary on Linux x64; if not, it compiles from source
  (`cargo install cargo-fuzz` built in ~2 min here).
- "this action will also verify SHA256 checksums for downloaded files"; needs
  `bash 3.2+, jq 1.3+, curl 7.34+` on non-Windows. nextest's own docs recommend exactly
  `- uses: taiki-e/install-action@nextest` (https://nexte.st/docs/installation/pre-built-binaries/)
  or `curl -LsSf https://get.nexte.st/latest/linux | tar zxf - -C ${CARGO_HOME:-~/.cargo}/bin`
  (that curl line is what was used on this VM).

### 1.5 `EmbarkStudios/cargo-deny-action@v2` (`action.yml@v2`)

Inputs: `command` (default `check`), `arguments` (default **`--all-features`** — override
to `--workspace` or `""` if all-features drags in FFmpeg/PipeWire bindings that need
system libs; note: `cargo deny` only needs `cargo metadata`, not a build, so
`--all-features` is fine unless a build-script-free metadata step fails),
`command-arguments`, `manifest-path` (`./Cargo.toml`), `log-level` (`warn`),
`rust-version` (updates rustup inside the container before running; image ships Rust
1.85.0 — enough for `cargo metadata` on an edition-2024 workspace), `credentials`,
`ssh-key`, `ssh-known-hosts`; `use-git-cli` is "Deprecated, this has no effect" (v2.1.1
fixed the breakage 2.1.0 introduced with that deprecation). Runs as a Docker action ⇒
**Linux runners only**. README recommends the matrix pattern with
`continue-on-error: ${{ matrix.checks == 'advisories' }}` to "Prevent sudden announcement
of a new advisory from failing ci". Source: https://github.com/EmbarkStudios/cargo-deny-action

### 1.6 `softprops/action-gh-release@v3` inputs (`action.yml@v3`)

`body`, `body_path`, `name`, `tag_name`, `draft`, `prerelease`, `preserve_order`,
`files` (glob list), `working_directory`, `overwrite_files` (default `true`),
`fail_on_unmatched_files`, `repository`, `token` (default `${{ github.token }}`),
`target_commitish`, `discussion_category_name`, `generate_release_notes`, `previous_tag`,
`append_body`, `make_latest`; outputs `url`, `id`, `upload_url`, `assets`. Needs
`permissions: contents: write`.

## 2. Runner images (actions/runner-images README + per-image READMEs, 2026-08-28)

Source: https://github.com/actions/runner-images/blob/main/README.md and
`images/{ubuntu,macos,windows}/*-Readme.md` fetched raw.

| Label | Resolves to | Notes |
|---|---|---|
| `ubuntu-latest` | **Ubuntu 24.04** x64 (image `20260823.283.1`, kernel 6.17 azure) | GA. Preinstalled: Rust **1.98.0** + rustup 1.29.0 + rustfmt/clippy, CMake 3.31.6, Clang 16/17/18, GCC 12–14, Node 22, Python 3.12, Git 2.55. **No ffmpeg/nasm/libclang-dev/pipewire-dev in the apt list** (grep of the README) — install via apt (§3) |
| `ubuntu-24.04` | same | |
| `ubuntu-26.04` | **Ubuntu 26.04** x64 (image `20260824.116.1`, kernel 7.0 azure) | **"Preview status"**. Announced 2026-06-11 (https://github.com/actions/runner-images/issues/14226): "Ubuntu 26.04 x64 and Arm are now available for all GitHub Actions users" but "some software may be unstable". Rust 1.98.0, CMake 4.4.2, Clang 20/21/22, GCC 13–15, Python 3.14, Node 24. No GA / `ubuntu-latest` migration date published; README: "the `-latest` migration process is gradual and happens over 1-2 months" |
| `ubuntu-22.04` | Ubuntu 22.04 | deprecation begins **2026-09-17**, unsupported by 2027-04-17 (issue #14254) |
| `ubuntu-24.04-arm`, `ubuntu-22.04-arm` | arm64, GA | listed in **both** the public and the private repo tables of https://docs.github.com/en/actions/reference/runners/github-hosted-runners (private: 2 vCPU/8 GB) |
| `ubuntu-26.04-arm` | arm64 preview | |
| `ubuntu-slim` | Ubuntu, **1 vCPU / 5 GB RAM**, x64 | docs: "available in both public and private repositories … a lower-cost option for running lightweight operations"; billed at `actions_linux_slim` **$0.002/min** vs $0.006 for 2-core — ideal for `cargo fmt --check`, `cargo deny`, docs |
| `macos-latest` | **macOS 26 arm64** (Tahoe 26.5.2, image `20260824.0517`) | 3 vCPU / 7 GB (both public and private). Xcode **26.6** default (also 26.5, 26.4.1), Clang/LLVM 21, CMake 4.4.0, Rust 1.97.1 preinstalled. `macos-15` (arm64), `macos-15-intel`, `macos-26-intel` (x64) exist; **`macos-13` no longer exists**; `macos-14*` deprecated (unsupported by 2026-11-02, issue #13518); `xcode-27` preview |
| `windows-latest` | **Windows Server 2025** (10.0.26100, image `20260824.239`) | Visual Studio Enterprise **2022 17.14**, LLVM 20.1.8, CMake 3.31.6, Rust 1.98.0, no nasm. `windows-2025-vs2026`, `windows-2022`, `windows-11-arm`, `windows-11-vs2026-arm` also exist |

Runner sizes (docs "GitHub-hosted runners reference"): **private repos get 2-core Linux/
Windows x64 (8 GB)** vs 4-core (16 GB) for public repos; macOS arm64 is 3-core/7 GB either way.

## 3. apt package versions on the Ubuntu images (Launchpad API, `pocket=Release`)

Queried `https://api.launchpad.net/1.0/ubuntu/+archive/primary?ws.op=getPublishedBinaries&…`
for **noble** (24.04 = `ubuntu-latest`) and **resolute** (26.04). Runners also have
`-updates`/`-security` enabled, so patch suffixes may be newer; majors are what matter.

| Package | noble (`ubuntu-latest`) | resolute (`ubuntu-26.04`, this VM) | Impact |
|---|---|---|---|
| `libavcodec-dev` / `ffmpeg` | **7:6.1.1-3ubuntu5 → FFmpeg 6.1** | **7:8.0.1-3ubuntu2 → FFmpeg 8.0.1** | The plan says "FFmpeg ≥ 7.x". `ffmpeg-sys-next 9.0.0` builds against 6.1 (its CI matrix includes "6.1", see `docs/research/codecs.md` §2), but **FFmpeg 8-only APIs (`AV_HWDEVICE_TYPE_AMF`, D3D12VA, Vulkan encode…) are absent on 24.04**. Options: (a) run the FFmpeg-feature job on `ubuntu-26.04` (preview; matches the dev VM's 8.0.1); (b) stay on 24.04 and gate FFmpeg-8-only code with the `ffmpeg_8_0` cfg that ffmpeg-sys-next emits; (c) build FFmpeg via ffmpeg-sys-next's `build` feature (slow, needs nasm/yasm). Recommendation: **(a) + (b)** — matrix `[ubuntu-24.04, ubuntu-26.04]` for the media job, 26.04 `continue-on-error: true` while it is preview |
| `libpipewire-0.3-dev` / `libspa-0.2-dev` | 1.0.5-1 | 1.6.2-1ubuntu1 | `pipewire = "=0.10.1"` with feature `v1_0_0` only (wayland.md §PipeWire) |
| `libei-dev` | 1.2.1-1 | 1.5.0-3 | **Not needed**: `reis 0.7.1` is pure Rust (`reis-0.7.1/Cargo.toml`: `build = false`, no `*-sys` deps; wayland.md line 57). Don't apt-install it |
| `libopus-dev` | 1.4-1build1 | 1.6.1-1 | only if the opus crate links system libopus (codecs.md) |
| `libasound2-dev` | 1.2.11-1build2 | 1.2.15.3-1ubuntu1 | cpal/alsa-sys |
| `libxkbcommon-dev` | 1.6.0-1build1 | 1.13.1-1 | xkbcommon crate (if linking) |
| `libwayland-dev` | 1.22.0-2.1build1 | 1.24.0-2 | only for ashpd `wayland` feature — not in v1 (wayland.md) |
| `libgtk-3-dev` | 3.24.41-4ubuntu1 | 3.24.52-0ubuntu1 | rfd/tray (GTK backends) |
| `libayatana-appindicator3-dev` | 0.5.93-1build3 | 0.5.94-1build1 | tray-icon on Linux |
| `libclang-dev` | 1:18.0-59~exp2 (libclang 18) | 1:21.1.6-71 | bindgen `runtime` needs `libclang.so` — `clang`/`libclang-dev` (ffmpeg-sys-next, pipewire-sys, alsa-sys w/ `use-bindgen`) |
| `nasm` | 2.16.01-1build1 | 3.01-1 | openh264 asm (3× faster, optional), rav1e/rav1d `asm`; FFmpeg from source |
| `libvulkan-dev` | 1.3.275.0-1build1 | 1.4.341.0-1 | wgpu Vulkan headers not needed (ash dlopens), harmless |
| `libdbus-1-dev` | 1.14.10-4ubuntu4 | 1.16.2-2ubuntu4 | not needed by zbus (pure Rust) |
| `libudev-dev` | 255.4-1ubuntu8 | 259.5-0ubuntu3 | gilrs (libudev-sys) |

One-liner for the Linux media job on 24.04/26.04 (trimmed vs the current `ci.yml`: no
`libei-dev`, no `libavformat/avfilter/avdevice-dev` unless those ffmpeg-next features are on):

```yaml
- run: |
    sudo apt-get update
    sudo apt-get install -y --no-install-recommends \
      pkg-config cmake nasm clang libclang-dev \
      libavcodec-dev libavutil-dev libswscale-dev \
      libpipewire-0.3-dev libspa-0.2-dev libopus-dev libasound2-dev \
      libxkbcommon-dev libgtk-3-dev libayatana-appindicator3-dev libudev-dev
```

## 4. Billing / limits for a private repo on the free plan

Sources: https://docs.github.com/en/billing/managing-billing-for-your-products/about-billing-for-github-actions ,
https://docs.github.com/en/billing/reference/actions-runner-pricing ,
https://docs.github.com/en/actions/reference/limits , https://docs.github.com/en/actions/reference/runners/github-hosted-runners

- Included per month: **GitHub Free (personal): 2,000 minutes, 500 MB artifact storage,
  10 GB cache per repository** (Pro 3,000 min / 1 GB; Team 3,000 / 2 GB). Minutes "reset to
  the full amount at the start of each billing cycle" (no rollover). Public repos: "The use of
  standard GitHub-hosted runners is free". Larger runners are always paid, even on public repos.
- Per-minute rates (billing SKUs): Linux 1-core `actions_linux_slim` **$0.002**, Linux 2-core
  **$0.006**, Linux arm64 2-core **$0.005**, Windows 2-core (x64 or arm64) **$0.010**,
  macOS 3/4-core **$0.062**. The docs pages fetched today no longer print a "minute
  multiplier" table; the search snippet of docs.github.com/en/actions/concepts/billing-and-usage
  still says jobs on Windows and macOS "consume minutes at 2 and 10 times the rate that jobs
  on Linux runners consume". **Budget with 1× / 2× / 10×** (rates give 1.67× / 10.3×).
- Concurrency (limits page): Free plan **20 concurrent jobs, max 5 macOS**; job ≤ 6 h;
  workflow ≤ 35 days; `GITHUB_TOKEN` API 1,000 req/h/repo; matrix ≤ 256 jobs; cache 10 GB/repo.
- Budget arithmetic for Tornect: one Linux lint+test run ≈ 10–15 min once cached (Arti +
  quinn + tests); a macOS `cargo check` job of 6 min costs **60 Linux-minutes**, Windows
  2× ⇒ 12. With ~2,000 min/month: run the **Linux job on every PR/push**, run **Windows and
  macOS only on `main` pushes and tags** (already `if: github.event_name != 'pull_request'`
  in `ci.yml`), keep them to `cargo check`/`cargo test -p tornect-core -p tornect`, put
  `fmt`/`deny`/`doc` on `ubuntu-slim` (1/3 the price), and use `concurrency:
  cancel-in-progress: true` (already present). The `gh api users/…/settings/billing/actions`
  endpoint needs the `user` OAuth scope (`gh auth refresh -h github.com -s user`) if the
  orchestrator wants to read remaining minutes from CI.

## 5. Rust toolchain facts for CI

- Edition 2024 is stable since **Rust 1.85.0 (2025-02-20)** (https://doc.rust-lang.org/edition-guide/rust-2024/index.html,
  "Release version 1.85.0"). Workspace has `edition = "2024"`, `resolver = "3"`,
  `rust-version = "1.90"` — fine on 1.96 locally and on CI's 1.98 (`@stable`).
- `ffmpeg-sys-next 9.0.0` needs ≥ 1.88 (let-chains, codecs.md); `windows 0.62.2`
  `rust-version = "1.82"`; objc2 family `1.71`; all under our 1.90 MSRV.
- Because `@stable` on CI floats (1.98 today), **new clippy lints can turn the `-D warnings`
  gate red without any code change**. Mitigation options: (a) pin CI to the same version as
  the dev VM with `dtolnay/rust-toolchain@1.96.0` and bump deliberately; (b) add a
  `rust-toolchain.toml` (`[toolchain] channel = "1.96.0" components = ["rustfmt","clippy"]`)
  — both dtolnay and rust-cache honor it (rust-cache hashes it). Recommendation: **(b)**
  so local and CI agree; `rustup update` locally when bumping.
- Cross targets: `rustup target add x86_64-pc-windows-msvc aarch64-apple-darwin` (already
  done on the VM) is enough for `cargo check --target …`; no `link.exe`/Apple linker is
  needed because `check` stops before linking (verified §0). For `aarch64-unknown-linux-gnu`
  in the cross-check job, same story. `cargo test`/`build` for those targets still needs
  the real OS runner.
- Nightly: `nightly-2026-08-28` (rustc 1.100.0-nightly e457a7b0d 2026-08-27) is the newest
  manifest; pin a **dated nightly** for the fuzz job so the ASan/`-Z` surface doesn't move.

## 6. cargo-fuzz — nightly vs stable, verified

cargo-fuzz README: "This also needs a nightly compiler since it uses some unstable
command-line flags" (https://github.com/rust-fuzz/cargo-fuzz). Source reality
(`/tmp/crates-src/cargo-fuzz-0.13.2/src/project.rs:178-260`): the always-on flags are
`-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4
-Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-pc-table
-Cllvm-args=-sanitizer-coverage-trace-compares --cfg fuzzing
-Cllvm-args=-simplifycfg-branch-fold-threshold=0 -Cdebug-assertions -Ccodegen-units=1`
(all stable `-C` flags); **only the sanitizer adds `-Zsanitizer=<x>`** (line 221-250;
`has_sanitizers_on_stable()` in `rustc_version.rs:93` is a `u32::MAX` placeholder — no
stable release supports sanitizers yet; `rustc -C help | grep -i sanit` on 1.96 prints
nothing). `-Zbuild-std` is only added for MemorySanitizer/`--careful`.

Verified here (§0): `cargo fuzz build -s none` and `cargo fuzz run -s none` **work on
stable 1.96**; default (ASan) build fails with `error: 1 nightly option were parsed`.

Recommended CI layout:

```yaml
  fuzz-smoke:              # stable, cheap, always on: proves targets compile + 30 s each
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
        with: { workspaces: ". -> target\nfuzz -> fuzz/target" }
      - uses: taiki-e/install-action@v2
        with: { tool: cargo-fuzz@0.13.2 }
      - run: cargo fuzz build -s none
      - run: for t in $(cargo fuzz list); do cargo fuzz run -s none "$t" -- -max_total_time=30; done

  fuzz-asan:               # nightly + AddressSanitizer, main only, allowed to fail
    if: github.event_name != 'pull_request'
    continue-on-error: true
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: dtolnay/rust-toolchain@master
        with: { toolchain: nightly-2026-08-28 }
      - uses: taiki-e/install-action@v2
        with: { tool: cargo-fuzz@0.13.2 }
      - run: cargo +nightly-2026-08-28 fuzz run envelope_decode -- -max_total_time=600
```

Notes: `cargo fuzz init` (0.13.2) writes `fuzz/Cargo.toml` with `edition = "2024"`,
`libfuzzer-sys = "0.4"` (latest **0.4.13**, 2026-06-04), `[package.metadata] cargo-fuzz = true`,
`publish = false`, and one `[[bin]]` per target with `test = false, doc = false, bench = false`
(captured from the probe). The `fuzz/` crate must **not** be a workspace member (cargo-fuzz
adds `[workspace]` to it, and its release profile is separate) — add `fuzz` to the root
`[workspace] exclude`. libFuzzer needs a C++ compiler (`cc` builds it) — present on all
GitHub images. Windows is unsupported by libFuzzer per README; run fuzzing on Linux only.

## 7. cargo-deny — config format and the current state of `deny.toml`

### 7.1 Versions
cargo-deny **0.20.2** (crates.io, 2026-07-09) = the version bundled by
`cargo-deny-action@v2.1.1` = the prebuilt musl binary used here. `cargo-deny-action` 2.1.0
notes: "PR#881 refactored the CLI … removing several deprecated options/flags/values";
`bans.std-replacements` lint added.

### 7.2 Config semantics (https://embarkstudios.github.io/cargo-deny/checks/licenses/cfg.html , …/advisories/cfg.html , …/cfg.html)
- `[licenses]` v2: fields `allow`, `exceptions`, `clarify`, `private`, `confidence-threshold`,
  `unused-allowed-license` (default `warn`), `include-dev`, `include-build`. **Removed and now
  errors**: `deny`, `copyleft`, `allow-osi-fsf-free`, `default`, `unlicensed`. The docs say the
  `version = 2` key is "no longer used" but 0.20.2 accepts it silently (verified run).
  Identifiers are exact SPDX: `LGPL-3.0` does **not** match `LGPL-3.0-only`.
- `[advisories]` v2: `db-path`, `db-urls`, `ignore` (`"RUSTSEC-…"`, `{ id, reason }`,
  `"crate@ver"` for yanked), `yanked` (`deny|warn|allow`), `unmaintained`
  (`all|workspace|transitive|none`, default `workspace`), `unsound`, `git-fetch-with-cli`,
  `maximum-db-staleness` (default `P90D`), `unused-ignored-advisory`. Removed:
  `vulnerability`, `unsound` (old form), `notice`, `severity-threshold`.
- `[graph]`: `targets` (with optional `features`), `all-features`, `no-default-features`,
  `features`, `exclude`, `exclude-dev`. `[output] feature-depth`.

### 7.3 What `cargo deny check` says about the repo today (0.20.2, exact output)
- `licenses FAILED`, 3 × `error[rejected]`:
  - `async_executors 0.7.0` — `license = "Unlicense"` (via `tor-rtcompat`). Add `"Unlicense"`
    (public-domain-equivalent, GPLv3-compatible). Other Unlicense crates are dual `OR MIT`
    and already pass.
  - `equix 0.7.1` and `hashx 0.9.1` — `license = "LGPL-3.0-only"` (Arti's onion-service
    PoW, via `tor-hscrypto`). Add `"LGPL-3.0-only"` (LGPLv3 is GPLv3-compatible; the
    existing `"LGPL-3.0"` entry is the deprecated SPDX id and never matches).
- 7 × `warning[license-not-encountered]` for unused allow entries (`Unicode-DFS-2016`,
  `OpenSSL`, `CDLA-Permissive-2.0`, `LGPL-2.1`, `LGPL-2.1-or-later`, `LGPL-3.0`, `GPL-3.0`) —
  harmless (`unused-allowed-license = "warn"` default); `ring 0.17.14` is `Apache-2.0 AND ISC`
  now, so `OpenSSL` is not needed for it. Set `unused-allowed-license = "allow"` or prune.
- `advisories FAILED`: `RUSTSEC-2023-0071` (Marvin attack, `rsa 0.9.10` ← `ssh-key-fork-arti`
  ← `tor-key-forge` ← `tor-hscrypto`; Arti never uses RSA for onion keys in our code path)
  and `RUSTSEC-2024-0436` (`paste` unmaintained ← `pwd-grp` ← `fs-mistrust`). Add to
  `[advisories] ignore` with `reason` strings and revisit at every Arti bump.
- `bans`: only `warning[duplicate]` (windows-sys ×3, syn ×3, hashbrown ×3, darling ×3,
  winnow ×2, windows-targets ×2 …) — expected with `multiple-versions = "warn"`.
- License distribution of the current graph (`cargo deny list -l license`): MIT 415,
  Apache-2.0 335, Unicode-3.0 19, GPL-3.0-or-later 11 (ours), BSD-3-Clause 8, Zlib 7, ISC 7,
  Unlicense 6, MPL-2.0 4, LGPL-3.0-only 2, BSD-2-Clause 2, Apache-2.0 WITH LLVM-exception 2,
  LGPL-3.0-or-later 1 (priority-queue, dual with MPL-2.0), CC0-1.0 1, BSL-1.0 1, 0BSD 1.
  All are GPL-3.0-or-later-compatible. Future GPL-incompatible risks to watch: none in the
  planned deps except **`libx264`/`build-license-gpl` (GPL-2.0-or-later — fine)** and any
  `OpenSSL`-licensed `openssl-sys` (avoid; rustls/ring only).

Drop-in `deny.toml` delta:

```toml
[advisories]
version = 2
yanked = "deny"
ignore = [
  { id = "RUSTSEC-2023-0071", reason = "rsa via ssh-key-fork-arti (tor-key-forge); Tornect never loads RSA keys, Arti onion services are ed25519-only" },
  { id = "RUSTSEC-2024-0436", reason = "paste (proc-macro) via pwd-grp/fs-mistrust in Arti; unmaintained, not a vulnerability" },
]

[licenses]
version = 2
allow = [
  "MIT", "Apache-2.0", "Apache-2.0 WITH LLVM-exception", "BSD-2-Clause", "BSD-3-Clause",
  "ISC", "Zlib", "MPL-2.0", "Unicode-3.0", "BSL-1.0", "CC0-1.0", "0BSD", "Unlicense",
  "LGPL-2.1-or-later", "LGPL-3.0-only", "LGPL-3.0-or-later", "GPL-3.0-or-later",
]
unused-allowed-license = "allow"
```

## 8. Cross-`cargo check` probes — exact manifests that compiled

### 8.1 Windows (`/tmp/probe-win-cross`, `cargo check --target x86_64-pc-windows-msvc` ⇒ green)

`windows` latest = **0.62.2** (2025-10-06, `rust-version = 1.82`, 677 cargo features,
`windows-core 0.62.2`); no newer crate release exists although the windows-rs repo has
tags `69…73` (release 73, 2026-02-17, "is only for the windows-metadata crate (0.60.0)" —
`gh api repos/microsoft/windows-rs/releases/tags/73`). Feature names verified against
`/tmp/crates-src/windows-0.62.2/Cargo.toml`:

```toml
[target.'cfg(windows)'.dependencies]
windows = { version = "=0.62.2", features = [
  "Foundation", "Graphics_Capture", "Graphics_DirectX", "Graphics_DirectX_Direct3D11",
  "Win32_Foundation", "Win32_Graphics_Direct3D", "Win32_Graphics_Direct3D11",
  "Win32_Graphics_Dxgi", "Win32_Graphics_Dxgi_Common", "Win32_Graphics_Gdi",
  "Win32_System_WinRT", "Win32_System_WinRT_Direct3D11", "Win32_System_WinRT_Graphics_Capture",
  "Win32_Media_Audio", "Win32_System_Com", "Win32_System_Com_StructuredStorage", "Win32_System_Variant",
  "Win32_UI_Input_KeyboardAndMouse", "Win32_UI_WindowsAndMessaging",
] }
```

Also present (verified names, not needed by the probe): `Win32_Media_Audio_Endpoints`,
`Win32_System_Threading`, `Win32_UI_HiDpi`, `Win32_System_LibraryLoader`,
`Win32_Devices_Display`, `Win32_System_Performance`, `Win32_Security`.

Signatures from the crate source that the probe exercised:
- `windows-0.62.2/src/Windows/Win32/Graphics/Direct3D11/mod.rs:3`
  `pub unsafe fn D3D11CreateDevice<P0>(padapter: P0, drivertype: D3D_DRIVER_TYPE, software: HMODULE, flags: D3D11_CREATE_DEVICE_FLAG, pfeaturelevels: Option<&[D3D_FEATURE_LEVEL]>, sdkversion: u32, ppdevice: Option<*mut Option<ID3D11Device>>, pfeaturelevel: Option<*mut D3D_FEATURE_LEVEL>, ppimmediatecontext: Option<*mut Option<ID3D11DeviceContext>>) -> Result<()>` — **`software` is a bare `HMODULE`, pass `HMODULE::default()`**, not `None` (first probe error).
- `…/Win32/System/WinRT/Direct3D11/mod.rs:3` `pub unsafe fn CreateDirect3D11DeviceFromDXGIDevice<P0>(dxgidevice: P0) -> Result<IInspectable>` → `.cast::<IDirect3DDevice>()`.
- `…/Win32/System/WinRT/Graphics/Capture/mod.rs:12` `IGraphicsCaptureItemInterop::CreateForMonitor<T>(&self, monitor: HMONITOR) -> Result<T>`; obtain it with `windows::core::factory::<GraphicsCaptureItem, IGraphicsCaptureItemInterop>()`.
- `…/Windows/Graphics/Capture/mod.rs:118/128` `Direct3D11CaptureFramePool::Create` / `CreateFreeThreaded(device, DirectXPixelFormat, numberofbuffers: i32, size: SizeInt32)`; then `pool.CreateCaptureSession(&item)`, `session.StartCapture()`, `pool.TryGetNextFrame()`.
- `…/Win32/UI/Input/KeyboardAndMouse/mod.rs:166` `pub unsafe fn SendInput(pinputs: &[INPUT], cbsize: i32) -> u32` with `INPUT { r#type: INPUT_MOUSE, Anonymous: INPUT_0 { mi: MOUSEINPUT { … } } }`.
- `…/Win32/Media/Audio/mod.rs:5375` `IMMDevice::Activate<T>(&self, dwclsctx: CLSCTX, pactivationparams: Option<*const PROPVARIANT>) -> Result<T>` is gated on **`all(feature = "Win32_System_Com_StructuredStorage", feature = "Win32_System_Variant")`** (second probe error: "no method named `Activate`" until both features were added). WASAPI loopback = `AUDCLNT_STREAMFLAGS_LOOPBACK` on an `IAudioClient` from `GetDefaultAudioEndpoint(eRender, eConsole)`.

### 8.2 macOS (`/tmp/probe-mac-cross`, `cargo check --target aarch64-apple-darwin` ⇒ green)

Versions (crates.io): `objc2` **0.6.4** (2026-02-26, MSRV 1.71), `objc2-foundation` /
`objc2-screen-capture-kit` / `objc2-core-graphics` / `objc2-core-media` /
`objc2-core-foundation` **0.3.2** (2025-10-04), `block2` 0.6.2, `dispatch2` 0.3.1.
`objc2-screen-capture-kit-0.3.2/Cargo.toml`: `objc2 >=0.6.2, <0.8.0`; features
`SCStream`, `SCShareableContent`, `SCError`, `SCContentSharingPicker`, `SCRecordingOutput`,
`SCScreenshotManager`, plus dep toggles `block2`, `dispatch2`, `objc2-core-media`
(`CMSampleBuffer`, `CMSync`, `CMTime`), `objc2-core-graphics` (`CGColor`, `CGDirectDisplay`,
`CGImage`, `CGWindow`), `objc2-av-foundation`, `objc2-uniform-type-identifiers`; `default`
enables all of them + `std`. `SCContentFilter` and `SCStreamConfiguration` live under the
`SCStream` feature (`src/generated/SCStream.rs:180, 374`).

```toml
[target.'cfg(target_os = "macos")'.dependencies]
objc2 = "=0.6.4"
objc2-foundation = { version = "=0.3.2", default-features = false, features = ["std", "NSArray", "NSError", "NSString", "NSEnumerator"] }
objc2-screen-capture-kit = { version = "=0.3.2", default-features = false, features = ["std", "SCStream", "SCShareableContent", "SCError", "block2", "dispatch2", "objc2-core-media", "objc2-core-graphics", "objc2-core-foundation"] }
objc2-core-graphics = { version = "=0.3.2", default-features = false, features = ["std", "CGEvent", "CGEventTypes", "CGEventSource", "CGRemoteOperation", "CGDirectDisplay", "CGGeometry"] }
objc2-core-foundation = { version = "=0.3.2", default-features = false, features = ["std", "CFCGTypes"] }
objc2-core-media = { version = "=0.3.2", default-features = false, features = ["std", "CMTime", "CMSampleBuffer"] }
block2 = "0.6"
dispatch2 = "0.3"
```

API surface exercised (from `/tmp/crates-src/objc2-core-graphics-0.3.2/src/generated/CGEvent.rs`
and `objc2-screen-capture-kit-0.3.2/src/generated/*.rs`):
- `CGEventSource::new(CGEventSourceStateID::HIDSystemState)`;
  `CGEvent::new_mouse_event(source: Option<&CGEventSource>, CGEventType::MouseMoved, CGPoint, CGMouseButton::Left)` (`CGEvent.rs:71`);
  `CGEvent::new_keyboard_event(source, keycode: u16, keydown: bool)` (`:94`);
  `CGEvent::post(CGEventTapLocation::HIDEventTap, event: Option<&CGEvent>)` (`:497`);
  `CGEvent::set_flags`, `set_location`, `set_integer_value_field` (`:254, :234, :326`) —
  these are **safe** fns in 0.3.2 (no `unsafe` needed except `tap_create*` / unicode string).
  `CGEventTypes.rs`: `CGEventTapLocation::HIDEventTap = 0`, `CGEventType::{LeftMouseDown=1, MouseMoved=5,…}`, `CGMouseButton::Left = 0`.
- `SCShareableContent::getShareableContentWithCompletionHandler(&RcBlock<dyn Fn(*mut SCShareableContent, *mut NSError)>)`
  (`SCShareableContent.rs:253`), `content.displays() -> Retained<NSArray<SCDisplay>>` (`:341`),
  `SCDisplay::displayID() -> CGDirectDisplayID` (`:156`);
  `SCContentFilter::initWithDisplay_excludingWindows(SCContentFilter::alloc(), &display, &NSArray<SCWindow>)` (`SCStream.rs:263`);
  `SCStreamConfiguration::new()`, `setWidth/setHeight(usize)`, `setMinimumFrameInterval(CMTime)`,
  `setPixelFormat(OSType)`, `setCapturesAudio(bool)` (`:334, :391, :413, :430, :585`);
  `SCStream::initWithFilter_configuration_delegate(SCStream::alloc(), &filter, &cfg, None)` (`:896`),
  `addStreamOutput_type_sampleHandlerQueue_error` (`:921`). All `unsafe`.
- `objc2::AllocAnyThread` must be in scope for `Type::alloc()`; `block2::RcBlock::new`
  for completion handlers; `NSArray::firstObject()` needs only `NSArray`, iteration
  (`.iter()`) needs the `NSEnumerator` feature of objc2-foundation (probe error 1).

## 9. nextest & xtask

- nextest config: `.config/nextest.toml` at the workspace root; profile via `--profile ci`
  / `-P` / `NEXTEST_PROFILE`; example `[profile.ci] fail-fast = false` `slow-timeout = "60s"`;
  `[profile.ci.junit] path = "junit.xml"` writes JUnit under `target/nextest/ci/`
  (https://nexte.st/docs/configuration/). Verified `cargo nextest run --workspace` on this
  repo: 47 passed / 1 skipped.
- xtask pattern (https://github.com/matklad/cargo-xtask): `.cargo/config.toml`
  `[alias] xtask = "run --package xtask --"`, `xtask` crate as workspace member with
  `publish = false`; "doesn't require any other binaries besides `cargo` and `rustc`".
  The repo already has `xtask = "run --quiet --package xtask --"` — equivalent.

## 10. Reference CI skeleton (drop-in replacement for the pins in `.github/workflows/ci.yml`)

```yaml
name: CI
on:
  push: { branches: [main], tags: ["m*", "v*"] }
  pull_request:
  workflow_dispatch:
env: { CARGO_TERM_COLOR: always, CARGO_INCREMENTAL: 0, RUST_BACKTRACE: 1 }
concurrency: { group: ci-${{ github.ref }}, cancel-in-progress: true }
permissions: { contents: read }

jobs:
  quick:                                   # 1-core, ~$0.002/min
    runs-on: ubuntu-slim
    steps:
      - uses: actions/checkout@v7
      - uses: dtolnay/rust-toolchain@stable
        with: { components: rustfmt }
      - run: cargo fmt --all -- --check
      - uses: EmbarkStudios/cargo-deny-action@v2
        with: { command: check, arguments: --workspace }

  linux:
    runs-on: ubuntu-latest                 # 24.04 today; add ubuntu-26.04 to a matrix for FFmpeg 8
    steps:
      - uses: actions/checkout@v7
      - uses: dtolnay/rust-toolchain@stable
        with: { components: clippy }
      - uses: Swatinem/rust-cache@v2
      - uses: taiki-e/install-action@v2
        with: { tool: cargo-nextest@0.9.143 }
      - run: sudo apt-get update && sudo apt-get install -y --no-install-recommends pkg-config cmake nasm clang libclang-dev libavcodec-dev libavutil-dev libswscale-dev libpipewire-0.3-dev libspa-0.2-dev libopus-dev libasound2-dev libxkbcommon-dev libgtk-3-dev libayatana-appindicator3-dev libudev-dev
      - run: cargo clippy --workspace --all-targets --all-features -- -D warnings
      - run: cargo nextest run --workspace --all-features --profile ci
      - run: cargo doc --workspace --no-deps
        env: { RUSTDOCFLAGS: -D warnings }
      - uses: actions/upload-artifact@v7
        if: always()
        with: { name: junit-linux, path: target/nextest/ci/junit.xml, if-no-files-found: ignore }

  cross-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: dtolnay/rust-toolchain@stable
        with: { targets: "x86_64-pc-windows-msvc, aarch64-apple-darwin, aarch64-unknown-linux-gnu" }
      - uses: Swatinem/rust-cache@v2
      - run: cargo check --workspace --target x86_64-pc-windows-msvc
      - run: cargo check --workspace --target aarch64-apple-darwin
      - run: cargo check --workspace --target aarch64-unknown-linux-gnu

  native:                                   # 2x / 10x minutes → main + tags only
    if: github.event_name != 'pull_request'
    strategy: { fail-fast: false, matrix: { os: [windows-latest, macos-latest] } }
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v7
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo test -p tornect-core -p tornect -p xtask

  release:
    if: startsWith(github.ref, 'refs/tags/v')
    needs: [linux, cross-check, native]
    permissions: { contents: write }
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo build --profile dist -p tornect
      - uses: softprops/action-gh-release@v3
        with: { files: target/dist/tornect, generate_release_notes: true, fail_on_unmatched_files: true }
```

Add `.github/dependabot.yml` with `package-ecosystem: github-actions` so the floating
majors get bumped by PR; or replace `@vN` with the full SHAs in §1 (`@<sha> # v7.0.1`).

## 11. Gotchas (collected)

1. **Node 20 actions die on 2026-09-23** (§1.2): `actions/checkout@v4`, `upload-artifact@v4`,
   `rustsec/audit-check@v2` in/for our workflow must be replaced before then.
2. `ubuntu-latest` = 24.04 = **FFmpeg 6.1**, not the ≥ 7 the plan assumes; the dev VM and
   `ubuntu-26.04` (preview) have 8.0.1 (§3).
3. `cargo-deny-action` defaults to `--all-features`; it runs `cargo metadata` in an Alpine
   container with Rust 1.85 — no system libs needed, but pass `rust-version` if a future
   `Cargo.toml` needs newer cargo features (edition 2024 is fine on 1.85).
4. SPDX exactness: `LGPL-3.0` ≠ `LGPL-3.0-only` in cargo-deny; current `deny.toml` fails
   on Arti's `equix`/`hashx` and on `async_executors` (`Unlicense`) (§7.3).
5. cargo-fuzz: `fuzz/` must be excluded from the workspace; ASan needs nightly, `-s none`
   works on stable (§6). Fuzz corpora/artifacts are in `fuzz/corpus`, `fuzz/artifacts` —
   commit corpus, upload artifacts on crash.
6. `windows` crate: `D3D11CreateDevice`'s `software` param is `HMODULE`, and
   `IMMDevice::Activate` needs `Win32_System_Com_StructuredStorage` + `Win32_System_Variant` (§8.1).
7. objc2: `NSArray::iter()` requires objc2-foundation's `NSEnumerator` feature (§8.2).
8. Free-plan private repo: 2-core runners, 2,000 min/month, macOS = 10×; the workflow
   scope: the `gh` token lacked the `workflow` scope on M0 (`docs/VERIFICATION.md`) — run
   `gh auth refresh -h github.com -s workflow` before pushing `.github/workflows/*`.
9. CI `@stable` (1.98) is ahead of the VM (1.96): pin via `rust-toolchain.toml` or expect
   clippy drift.
10. `/tmp` tmpfs quota on the VM (§0): keep probe `target/`s and `TMPDIR` under `$HOME`.
11. rust-cache keys include all installed toolchains since 2.9.0 — the nightly fuzz job
    should use its own `shared-key` so it doesn't thrash the stable cache.

## 12. Open questions

1. When will `ubuntu-latest` flip to 26.04? No date in issue #14226; watch
   https://github.com/actions/runner-images/issues (the flip would silently move CI to FFmpeg 8 / libclang 21 / pipewire 1.6).
2. GitHub's billing pages no longer print the 1×/2×/10× multiplier table; the per-minute
   rates imply ≈1.7× for Windows. Whether *included* minutes are debited at 2× or 1.7× for
   Windows was not confirmable from the docs fetched (macOS ≈10× either way).
3. Do we want `cargo-audit` (issue-creating scheduled job via `actions-rust-lang/audit`)
   in addition to `cargo deny check advisories`? Same DB; deny already fails on the two
   Arti-inherited advisories.
4. Should the release job use `cargo-dist` (available via install-action) instead of a
   hand-rolled `action-gh-release` step? Deferred to M8 packaging.
5. Whether `ubuntu-slim` can run the Docker-based `cargo-deny-action` (Docker actions need
   the Docker daemon; slim image contents not verified) — if not, use
   `taiki-e/install-action@cargo-deny` + `cargo deny check` on slim, which needs no Docker.
