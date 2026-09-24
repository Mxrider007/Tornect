# Bundled pluggable transport: lyrebird

Tornect reaches Tor through bridges when direct Tor is blocked (decision M1-38,
`docs/research/bridges.md`). One helper binary serves both bridge types it uses — **obfs4** and
**Snowflake** — and webtunnel: **lyrebird**, taken unmodified from the Tor Project's signed
tor-expert-bundle. It is not committed to git. `cargo xtask pt-fetch` downloads it and runs the
checks below (section *`cargo xtask pt-fetch`*); `cargo xtask dist` runs the same checks and ships
it as `pt/lyrebird[.exe]` in each release zip (`docs/RELEASING.md`).

**Enforced at run time** (decision M1-40): Tornect hashes the `lyrebird` it is about to launch and
refuses one that does not match the member SHA-256 below, compiled into
`crates/tornect-signal/src/tor/bridges.rs` (`LYREBIRD_SHA256`). It looks next to the executable (or
in its `pt/` directory), then in `$TORNECT_PT_DIR`; never on `PATH`, never at a relative path. Only
an explicit `tor.pt_path` may run another build, and that is logged.

| field | value |
|---|---|
| upstream | Tor Browser **15.0.23** (stable, released 2026-09-15), lyrebird **0.8.1** |
| linux tarball | `https://archive.torproject.org/tor-package-archive/torbrowser/15.0.23/tor-expert-bundle-linux-x86_64-15.0.23.tar.gz` |
| linux sha256 | `08d49de27f542b8f73e2014e064d8320562b5d20019c03d4725c5a5249d97985` |
| windows tarball | `https://archive.torproject.org/tor-package-archive/torbrowser/15.0.23/tor-expert-bundle-windows-x86_64-15.0.23.tar.gz` |
| windows sha256 | `231dad6b9cb401a54c260db7046965ef04e4f72ff071b140d423fb5da281ab1e` |
| member (linux) | `tor/pluggable_transports/lyrebird` — sha256 `ee13ec155cf9b131a3e1b87bd6d697a10c42d04f2eaaeab6b1590c9971d41421` |
| member (windows) | `tor/pluggable_transports/lyrebird.exe` — sha256 `6e218e85f9a7ae2481f5402ded822471a9a9d0c7e66b05db3842b93fa5c1f02e` |
| licence notice | `docs/lyrebird.txt` from the same tarball (shipped alongside the binary as `pt/lyrebird.txt`; the same file in both tarballs) — sha256 `2331e6517a15ce87e2a1d2838c314ca1b8f3c7a347ac28d370a7fccdb5964f40` |
| signing key | Tor Browser Developers, primary `EF6E 286D DA85 EA2A 4BA7 DE68 4E2C 6E87 9329 8290`; the key is `packaging/pt/tor-browser-developers.asc` (from the WKD on 2026-09-21, `--export-options export-minimal`) |

## How the pins were established (2026-09-21, the build VM)

```bash
V=15.0.23; B=https://archive.torproject.org/tor-package-archive/torbrowser/$V
for os in linux-x86_64 windows-x86_64; do
  curl -fLO "$B/tor-expert-bundle-$os-$V.tar.gz"; curl -fLO "$B/tor-expert-bundle-$os-$V.tar.gz.asc"; done
curl -fLO "$B/sha256sums-signed-build.txt"; curl -fLO "$B/sha256sums-signed-build.txt.asc"
export GNUPGHOME=$(mktemp -d)
gpg --auto-key-locate nodefault,wkd --locate-keys torbrowser@torproject.org
gpg --fingerprint EF6E286DDA85EA2A4BA7DE684E2C6E8793298290      # must match exactly
gpg --output tor.keyring --export EF6E286DDA85EA2A4BA7DE684E2C6E8793298290
for f in tor-expert-bundle-{linux,windows}-x86_64-$V.tar.gz sha256sums-signed-build.txt; do
  gpgv --keyring ./tor.keyring "$f.asc" "$f"; done              # "Good signature" ×3 (subkey CAAE408A…)
grep -E "tor-expert-bundle-(linux|windows)-x86_64-$V\.tar\.gz$" sha256sums-signed-build.txt | sha256sum -c -
```

Result: three good signatures from the key above, both tarball hashes `OK` against the signed
list, and the pins in the table. The 7 obfs4 + 2 Snowflake bridge lines inside the bundle's
`pt_config.json` are byte-identical to `tornect-signal`'s `BUILTIN_OBFS4` / `BUILTIN_SNOWFLAKE`.

## `cargo xtask pt-fetch`

`cargo xtask pt-fetch [--linux] [--windows] [--offline]` (both platforms by default) repeats the
recipe below for one Tor Browser version, with every value above compiled into `xtask/src/pt.rs`:

1. It refuses to start unless its pins equal `LYREBIRD_SHA256` in
   `crates/tornect-signal/src/tor/bridges.rs` and the rows of this table (a gate test checks the
   same).
2. The tarball comes from `target/pt-fetch/15.0.23/` when its SHA-256 is the pin; otherwise it is
   downloaded with `curl --disable` (curl's default user agent, no `~/.curlrc`, https only) to a
   `.part` file and renamed into place only when it matches. A cached copy that does not match is
   deleted and fetched again.
3. The detached signature (`.asc`) is checked with the key file above alone: `gpg --dearmor`, then
   `gpgv --status-fd` in an empty home directory. Accepted: gpgv's success, a `VALIDSIG` whose
   primary key is `EF6E…8290`, and `GOODSIG`, or `EXPKEYSIG` for a signature made while the signing
   subkey was valid. `BADSIG`, `ERRSIG`, `NO_PUBKEY`, `REVKEYSIG` and `EXPSIG` refuse. Without `gpg`
   and `gpgv` on `PATH` the run prints "signature NOT CHECKED" and relies on the SHA-256 pins.
4. `tar` extracts only the two members into a scratch directory; each must match its pin, and the
   copy placed under `target/pt/<os>/` (at the member's path in the tarball, mode 0755 or 0644) is
   hashed again before it is renamed into place.

Any mismatch stops the run before anything is installed. The subkey that signed 15.0.23
(`CAAE 408A EBE2 288E 96FC 5D5E 1574 32CF 78A6 5729`) expires on 2026-10-26; from then gpgv says
`EXPKEYSIG` and pt-fetch says so. The key file also holds a newer signing subkey, `022D A248 432D
2A0E 0F54 E65E 316C 1FAC D62D 07D9` (created 2026-08-11, valid to 2028-11-28). Refresh the key file
from the WKD whenever `V` changes.

## Licences

lyrebird is BSD-2-Clause and includes GPL-3.0-or-later code (`meeklite/transport.go`), so a
Tornect release that ships it also points to its source: tag `lyrebird-0.8.1` at
https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird (and the Tor
Browser 15.0.23 build that produced this binary). Snowflake's client code is BSD-3-Clause. Both
are compatible with Tornect's GPL-3.0-or-later.

## Updating

Bump `V` and re-run the recipe; replace every hash in the table, the pins in `xtask/src/pt.rs`
and `LYREBIRD_SHA256` in `crates/tornect-signal/src/tor/bridges.rs` together (a release whose
bundled binary does not match it refuses to run it; `cargo xtask pt-fetch` refuses to run while
they differ); re-export the key file; diff the bundle's `pt_config.json` bridge lines against
`BUILTIN_OBFS4` / `BUILTIN_SNOWFLAKE`.
