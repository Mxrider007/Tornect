# Canonical licence texts

`cargo xtask dist` writes `THIRD_PARTY_LICENSES.txt` into each release zip (`xtask/src/licences.rs`,
`docs/RELEASING.md`). Most crates publish their own licence files, and those go in as published. A crate
that publishes none gets the canonical text of every licence its SPDX expression names, from this
directory: `<SPDX id>.txt`, where one text serves `-only`, `-or-later` and `+`. The gate test
`licences::tests::every_crate_in_both_build_graphs_maps_to_a_licence_text` fails when a crate in the Linux
or Windows build graph publishes no licence file and names a licence that has no text here.

Each file is an unchanged copy of the source below, taken on the build VM on 2026-09-24, offline. The gate test
`licences::tests::the_canonical_texts_match_their_sources_md_rows` checks every file against its SHA-256
here.

| File | Licence | Copied from | SHA-256 |
|---|---|---|---|
| `Apache-2.0.txt` | Apache License 2.0, with its appendix | Ubuntu 26.04's `/usr/share/common-licenses/Apache-2.0` (package `base-files`) | `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30` |
| `BSD-2-Clause.txt` | BSD 2-Clause | Rust 1.96.0's `share/doc/rust/licenses/BSD-2-Clause.txt` (the SPDX text, from the rust-docs component) | `f32fb3b417a194167cfad068223fc975ba96c5960513a10f66a3c28720aec1df` |
| `BSL-1.0.txt` | Boost Software License 1.0 | `LICENSE` of the crates `error-code` 3.4.0 and `xxhash-rust` 0.8.18 (the same bytes) | `c9bff75738922193e67fa726fa225535870d2aa1059f91452c411736284ad566` |
| `LGPL-3.0.txt` | GNU LGPL version 3 (it adds to the GNU GPL version 3, which is Tornect's `LICENSE`) | Ubuntu 26.04's `/usr/share/common-licenses/LGPL-3` | `e3a994d82e644b03a792a930f574002658412f62407f5fee083f2555c5f23118` |
| `MIT.txt` | MIT | Rust 1.96.0's `share/doc/rust/licenses/MIT.txt` (the SPDX text) | `b85dcd3e453d05982552c52b5fc9e0bdd6d23c6f8e844b984a88af32570b0cc0` |
| `MPL-2.0.txt` | Mozilla Public License 2.0 | Ubuntu 26.04's `/usr/share/common-licenses/MPL-2.0` | `fab3dd6bdab226f1c08630b1dd917e11fcb4ec5e1e020e2c16f83a0a13863e85` |
| `OFL-1.1.txt` | SIL Open Font License 1.1 | Rust 1.96.0's `share/doc/rust/licenses/OFL-1.1.txt` (the SPDX text) | `8eea8287e5876b539670cadb82e99f9a7afddec6f6730811be1daf25d2e9bcfd` |
| `Ubuntu-font-1.0.txt` | Ubuntu Font Licence 1.0 | `fonts/UFL.txt` of the crate `epaint_default_fonts` 0.36.2 | `2f0015108d68627bd788d313f529c21ff4da2c2c42a5e1f3883acc83480f9002` |

On 2026-09-24, 70 crates in each platform's graph published no licence file. Most are Arti's (`arti-client`,
the `tor-*` crates and their helpers) and egui's, under MIT OR Apache-2.0. The others name Apache-2.0, MIT,
BSD-2-Clause (`openh264`, `openh264-sys2`, whose OpenH264 text also comes from its `upstream/LICENSE`),
LGPL-3.0-only (`equix`, `hashx`), MPL-2.0 (`dynasm`, `dynasmrt`), LGPL-3.0-or-later OR MPL-2.0
(`priority-queue`), BSL-1.0 (`clipboard-win`, Windows only) and (MIT OR Apache-2.0) AND OFL-1.1 AND
Ubuntu-font-1.0 (`epaint_default_fonts`, whose font licences also come from its `fonts/`).
