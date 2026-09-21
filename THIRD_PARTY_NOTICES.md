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

## Rust crates

Every other dependency is a Rust crate listed in `Cargo.lock`, pinned and
justified in `docs/DEPENDENCIES.md`; `cargo deny check licenses` (`deny.toml`)
keeps them within the allowed licences.
