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

## Fonts and icons the window embeds

The window (`apps/tornect/src/ui/`) embeds these files whole with `include_bytes!` (subsetting them is a later
step). Each is an unchanged copy of the upstream file below, fetched anonymously on 2026-09-27. `cargo xtask dist`
puts each licence file's text into `THIRD_PARTY_LICENSES.txt` (part 1, `EMBEDDED` in `xtask/src/licences.rs`).

| File | What | Downloaded from | SHA-256 |
|---|---|---|---|
| `apps/tornect/assets/fonts/manrope-regular.ttf` | Manrope 400 | `https://raw.githubusercontent.com/googlefonts/manrope/468c0dbe38efa331b80bfe9448256abe27be44c3/fonts/ttf/manrope-regular.ttf` (the upstream repository Google Fonts' `ofl/manrope/METADATA.pb` names) | `d23d6eedf51dd495138aa1a83588027d4a63549cdfcc2fa5e0d8e84e09cf4cb1` |
| `apps/tornect/assets/fonts/manrope-medium.ttf` | Manrope 500 | the same commit, `fonts/ttf/manrope-medium.ttf` | `502ee33a6e140ad6ef10ef8b762a8e5cf01f33316f318800795725f4cfd539d9` |
| `apps/tornect/assets/fonts/manrope-semibold.ttf` | Manrope 600 | the same commit, `fonts/ttf/manrope-semibold.ttf` | `f43edb46a08e1538413ea2383ef01ed93cdab191a2c57d2489d9590985858cf7` |
| `apps/tornect/assets/fonts/manrope-bold.ttf` | Manrope 700 | the same commit, `fonts/ttf/manrope-bold.ttf` | `484d10f0683e9e9f588de978f70cd3ad17cb3522bc0ca6efc4491c83429d323c` |
| `apps/tornect/assets/fonts/Manrope-OFL.txt` | Manrope's licence (SIL OFL 1.1, with its copyright line) | the same commit, `OFL.txt` | `58172e0c0fac2cda8a37b348164bb55e44b0e69051e557e92b1d3f6910141f7b` |
| `apps/tornect/assets/fonts/JetBrainsMono-Regular.ttf` | JetBrains Mono 400 | `fonts/ttf/JetBrainsMono-Regular.ttf` of `https://github.com/JetBrains/JetBrainsMono/releases/download/v2.304/JetBrainsMono-2.304.zip` (zip SHA-256 `6f6376c6ed2960ea8a963cd7387ec9d76e3f629125bc33d1fdcd7eb7012f7bbf`) | `a0bf60ef0f83c5ed4d7a75d45838548b1f6873372dfac88f71804491898d138f` |
| `apps/tornect/assets/fonts/JetBrainsMono-Medium.ttf` | JetBrains Mono 500 | the same zip, `fonts/ttf/JetBrainsMono-Medium.ttf` | `31c92d01a8a08528b718a43addf0ad3df0af2ca4b7b3290a452f70f358e14d3d` |
| `apps/tornect/assets/fonts/JetBrainsMono-SemiBold.ttf` | JetBrains Mono 600 | the same zip, `fonts/ttf/JetBrainsMono-SemiBold.ttf` | `1b3bfa1ed5665a4ce3f9feb68d2d4e40e70bf8b4b7d9a3edd418f321b4e166a0` |
| `apps/tornect/assets/fonts/JetBrainsMono-OFL.txt` | JetBrains Mono's licence (SIL OFL 1.1, with its copyright line) | the same zip, `OFL.txt` | `30f0c136e3c88e422d0791acd97238870f9054a9729bc34cf2ff0d4ed8cac4ad` |
| `apps/tornect/assets/icons/lucide.ttf` | Lucide 1.48.0 as an icon font | `lucide-font/lucide.ttf` of `https://github.com/lucide-icons/lucide/releases/download/1.48.0/lucide-font-1.48.0.zip` (zip SHA-256 `25976e2016c1ac4cf86b1d82202cefb186ddb11d692f6d0736e9d0b01415f7c8`) | `eaf30a2a0d2ec0cfbf7ab69ed6dc6e39b7e5e2f0255c17856dcb0b73a15584bb` |
| `apps/tornect/assets/icons/Lucide-LICENSE.txt` | Lucide's licence (ISC; the icons derived from Feather under MIT) | `https://raw.githubusercontent.com/lucide-icons/lucide/1.48.0/LICENSE` | `b495047bd93a9b06913511076f504daba17d5bbeb3e0650f3bb53a4220329c57` |

The glyph table in `apps/tornect/src/ui/icons.rs` takes each icon's code point from `lucide-font/codepoints.json`
of the same zip (SHA-256 `65faa5131cc840e8f400e7262462cff817c4741552a5c707e8a692885adc66ce`), which is not
committed.

## The word list of the device words

`crates/tornect-core` embeds this file whole with `include_str!` (`src/words.rs`, `docs/PLAN.md` §B.6.1): an
unchanged copy of the upstream file, fetched anonymously on 2026-09-28. The same SHA-256 is pinned in
`words::WORDLIST_SHA256` and checked by `words::tests::the_list_is_bip39_english`.

| File | What | Downloaded from | SHA-256 |
|---|---|---|---|
| `crates/tornect-core/data/bip39-english.txt` | The BIP 39 English word list (2048 words, one per line) | `https://raw.githubusercontent.com/bitcoin/bips/ce1862ac6bcffa1dd20aad858380e51e66e949ea/bip-0039/english.txt`: commit `ce1862ac6bcffa1dd20aad858380e51e66e949ea` of `bitcoin/bips` ("Added bip39 english wordlist", 2014-02-07), the only commit that touches `bip-0039/english.txt` (GitHub API, 2026-09-28); the file on `master` has the same bytes | `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda` |

The list's licence terms were not looked up (only the list itself was fetched), so it is not in `xtask`'s
`EMBEDDED` and `THIRD_PARTY_LICENSES.txt` carries no text for it: open before the release.

## The word list of the passphrase generator

`crates/tornect-core` embeds this file whole with `include_str!` (`src/unattended/password.rs`, `docs/PLAN.md`
§B.8.7.1 ④, decision M1-19): an unchanged copy of the file EFF publishes, fetched over HTTPS on 2026-10-02, dice
numbers included; the generator skips that column. The same SHA-256 is pinned in `password::EFF_LONG_LIST_SHA256`
and checked by `password::tests::the_eff_list_matches_its_checksum`. Before it was used, the file was checked to
hold 7776 lines of five dice digits (1 to 6), a tab and a word, ASCII only, with LF line ends and a final newline,
7776 different words, and the same words in the same order as the words-only copy that the Debian package
`python3-passlib` ships.

| File | What | Downloaded from | SHA-256 |
|---|---|---|---|
| `crates/tornect-core/data/eff_large_wordlist.txt` | EFF's long word list for passphrases (7776 words, each after its five dice numbers and a tab; 108800 bytes) | `https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt`, 2026-10-02 | `addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e` |

The list's licence terms were not looked up (only the list itself was fetched), so it is not in `xtask`'s
`EMBEDDED` and `THIRD_PARTY_LICENSES.txt` carries no text for it: open before the release, as for the BIP 39 list.
