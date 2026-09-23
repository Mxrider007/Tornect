# Releasing

Until M8 brings installers (MSI/winget, a notarized `.dmg`, AppImage/Flatpak; `docs/PLAN.md`), a
release is a GitHub **pre-release** with two zips, `SHA256SUMS` and release notes, all made by
`cargo xtask dist` on a Linux x86_64 machine.

## What must be true before a tag

1. `main` is clean and `cargo xtask verify` is green on it. The gate fails without cargo-deny
   (decision B3-6), so "green" includes advisories, bans, licences and sources.
2. Nothing the release claims is red. A `-slice.N` tag claims the vertical slice only; the `m<N>`
   milestone tags keep their own rule (CLAUDE.md, ground rule 1).
3. `docs/VERIFICATION.md` says, per platform, what was verified live and what is still
   NEEDS-DEVICE, and the release notes repeat that without upgrading anything.
4. The notes name the latest security review and the commits after it that no review has read.
5. `cargo xtask dist` ran on that commit with a clean tree: each zip's `BUILD-INFO.txt` names the
   commit without "WITH UNCOMMITTED CHANGES", and its lyrebird `signature` line says "good" (not
   "NOT CHECKED").
6. The smoke tests below passed on the unpacked zips.
7. The zips carry the licence texts and notices that the bundled dependencies require of a binary
   distribution. **Not met yet** (`docs/VERIFICATION.md`, *Release tooling*): the zips hold
   `LICENSE`, `THIRD_PARTY_NOTICES.md` and lyrebird's notice, but not the texts of the 500-odd
   crates linked in, nor those of OpenH264, zstd and ring's C code. Waiving this for a pre-release is the
   operator's decision.

## Steps

1. `git status` (clean), then the gate. On mx-vm every heavy cargo command runs in its own
   transient scope, so that systemd-oomd can kill only the build:
   `systemd-run --user --scope --quiet -- env CARGO_BUILD_JOBS=2 TMPDIR=$PWD/target/tmp cargo xtask verify`
2. The artifacts, with the same wrapper: `cargo xtask dist` (both platforms; `--linux` or
   `--windows` for one). It needs llvm-mingw 20260908 (`$LLVM_MINGW`, else
   `~/.local/opt/llvm-mingw-20260908-ucrt-ubuntu-22.04-x86_64`; its clang must be the pinned one),
   nasm, `zip`/`unzip`, binutils (`strip`, `readelf`, `objdump`), `gpg` + `gpgv`, and `curl` and the
   network the first time (the tor-expert-bundles). Per platform it:
   - fetches or re-checks lyrebird (`cargo xtask pt-fetch`, `packaging/pt/SOURCES.md`);
   - runs `cargo build --locked --release --target <triple> -p tornect` into `target/dist/cargo/`
     with `LZMA_API_STATIC=1` and its own rustflags added to `.cargo/config.toml`'s:
     `--remap-path-prefix` for the workspace and `CARGO_HOME`, and on Windows
     `-C link-arg=-Wl,--no-insert-timestamp`;
   - refuses an executable that loads anything beyond glibc and the GCC runtime (Linux), or that
     imports a toolchain DLL (`lib*`, `vcruntime*`, `msvcp*`) or holds a link time in its PE header
     (Windows);
   - strips the debug info (symbols stay), stages the zip's files in `target/dist/stage/` with the
     commit's time and fixed modes, refuses any file that holds the build machine's home path, and
     writes `target/dist/tornect-<version>-<os>-x86_64.zip`, tested with `unzip -t`;
   - last, `target/dist/SHA256SUMS` over the zips of this run.
3. Check: `cd target/dist && sha256sum -c SHA256SUMS`; read both `BUILD-INFO.txt`.
4. Smoke tests, each in a fresh `--home` under `target/tornect-test/`:
   - Linux, from the unpacked zip: `./tornect --version`, `./tornect --home <dir> id`,
     `./tornect --home <dir> doctor`, whose `tor:` line must name the zip's `pt/lyrebird`.
   - Windows: the same with `tornect.exe` under Wine (Wine is not Windows: this proves the
     executable starts, its imports resolve and it accepts the bundled `lyrebird.exe`), and on a
     Windows machine when one is at hand.
5. Tag the commit that `BUILD-INFO.txt` names, then push the tag:
   `git tag -a v<version>-slice.<N> <commit> -m "Tornect <version>, slice pre-release <N>"`.
6. Publish (the Git agent's step, with the operator's approval):
   `gh release create v<version>-slice.<N> --prerelease --title "Tornect <version> (slice <N>)"
   --notes-file <notes.md> target/dist/tornect-<version>-linux-x86_64.zip
   target/dist/tornect-<version>-windows-x86_64.zip target/dist/SHA256SUMS`
7. Download the three assets from the release page into an empty directory and run
   `sha256sum -c SHA256SUMS` there.

## Tag form

`v<version>-slice.<N>`: `<version>` is the workspace version in `Cargo.toml` (what `tornect
--version` prints), and `N` counts the slice pre-releases of that version from 1, for example
`v0.1.0-slice.1`. These are always published with the pre-release flag. Plain `v<version>` is kept
for the first full release; `m0` … `m8` stay milestone tags.

## Checksums

`SHA256SUMS` holds one line per zip, in the format `sha256sum -c` reads. Inside each zip,
`BUILD-INFO.txt` lists the SHA-256 of every other file, and lyrebird's also equals the pin
compiled into Tornect, which refuses to run any other lyrebird. Nothing is signed yet (no release
key exists), so the checksums prove only that a download matches what the release page lists.

## Reproducing a build

`git checkout <the commit in BUILD-INFO.txt>`, then `cargo xtask dist` with the toolchain that
BUILD-INFO.txt names: rustc from `rust-toolchain.toml`, llvm-mingw 20260908, and the same nasm,
binutils and Info-ZIP versions. Every file in a zip carries the commit's time and a fixed mode, the
zip has no owner ids, and the paths of the build machine are remapped, so the zip depends only on
its files.

Checked on mx-vm on 2026-09-23 (`docs/VERIFICATION.md`, *The zips reproduce*): two builds from scratch
at one commit gave bit-identical executables and byte-identical zips. No second machine has tried.
The Linux C compiler, nasm, binutils, glibc and Info-ZIP are the build host's own, so use the same
distribution release (Ubuntu 26.04 so far) with the versions `BUILD-INFO.txt` records.
