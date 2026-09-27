# Third-party notices

Tornect is GPL-3.0-or-later (`LICENSE`). It includes or ships the following
third-party material under their own licences.

## Chromium key-code table (`crates/tornect-input/src/keymap.rs`)

Derived from Chromium's `ui/events/keycodes/dom/dom_code_data.inc` (fetched
2026-09-21). BSD-3-Clause:

```
Copyright 2015 The Chromium Authors

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google LLC nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## lyrebird (bundled pluggable transport, `packaging/pt/SOURCES.md`)

`lyrebird` / `lyrebird.exe` 0.8.1 is shipped unmodified from the Tor Project's
tor-expert-bundle 15.0.23. It is BSD-2-Clause and includes GPL-3.0-or-later code
(`meeklite/transport.go`); its own licence text travels next to the binary as
`lyrebird.txt`. Source: tag `lyrebird-0.8.1`,
https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird .
The Snowflake client code inside it is BSD-3-Clause.

## OpenH264 (`openh264` / `openh264-sys2` crates, built from source)

Cisco OpenH264 2.6.0 and its Rust bindings are BSD-2-Clause
(`openh264-sys2-0.9.8/upstream/LICENSE`). Tornect builds the codec from source;
Cisco's MPEG LA patent coverage applies only to Cisco's own binary module
(see `docs/research/slice.md` §3; the plan defers the decision to M8).

## equix and hashx (LGPL-3.0-only)

`equix` and `hashx`, which Arti uses for the proof of work of onion services, are
under the GNU Lesser General Public License 3.0 and are linked into the
executable statically. Tornect's complete source is free software under the
GPL-3.0-or-later, so the executable can be rebuilt from the commit that each
zip's `BUILD-INFO.txt` names with changed versions of those crates
(`docs/RELEASING.md`, *Reproducing a build*). Their licence text is in each zip's
`THIRD_PARTY_LICENSES.txt`, and the GPL it builds on is `LICENSE`.

## Fonts and icons of the window (`apps/tornect/assets/`)

The window embeds these files unchanged; `packaging/licenses/SOURCES.md` gives
where each came from and its SHA-256, and each release zip's
`THIRD_PARTY_LICENSES.txt` carries their licence texts in full.

| Files | What | Licence (the upstream file, verbatim) |
|---|---|---|
| `fonts/manrope-{regular,medium,semibold,bold}.ttf` | Manrope, the text font | SIL Open Font License 1.1 (`fonts/Manrope-OFL.txt`) |
| `fonts/JetBrainsMono-{Regular,Medium,SemiBold}.ttf` | JetBrains Mono 2.304, for IDs, codes and numbers | SIL Open Font License 1.1 (`fonts/JetBrainsMono-OFL.txt`) |
| `icons/lucide.ttf` | Lucide 1.48.0, the icons, as a font | ISC; the icons derived from Feather are MIT (`icons/Lucide-LICENSE.txt`) |

## Rust crates, and everything else built into the program

Every other dependency is a Rust crate listed in `Cargo.lock`, pinned and
justified in `docs/DEPENDENCIES.md`; `cargo deny check licenses` (`deny.toml`)
keeps them within the allowed licences.

Each release zip carries `THIRD_PARTY_LICENSES.txt`, which `cargo xtask dist`
generates for its platform (`xtask/src/licences.rs`, `docs/RELEASING.md`): every
crate the executable is built from, with its version and licence expression,
and the licence texts those crates publish (or, for the few that publish none,
the canonical texts in `packaging/licenses/`); the C code built in from inside
crates (OpenH264, ring's fiat-crypto, Zstandard, liblzma, SQLite), egui's
fonts, the window's own fonts and icons (above), the Rust standard library's
notices, and for Windows the statically linked llvm-mingw runtime (libc++,
libunwind, compiler-rt, mingw-w64's).
