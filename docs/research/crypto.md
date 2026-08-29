# Research note: cryptography crates and the 2026 RustCrypto / rand alignment

Date: 2026-08-28. Verified against the crates.io API, the extracted crate sources under
`/tmp/crates-src/<crate>-<version>/` (downloaded from `static.crates.io`), the cargo
registry sources under `~/.cargo/registry/src/index.crates.io-*/`, and a compile+run
probe on this VM (`/tmp/probe-crypto`, see §14). Every claim cites a URL or a path.
Toolchain here: `rustc 1.96.0 (ac68faa20 2026-05-25)`, `cargo 1.96.0`.

---

## 0. TL;DR for implementers

There are **two incompatible crypto "stacks"** alive in the ecosystem today, and Tornect
must carry both (they coexist fine in one binary; Cargo treats different majors as
different crates):

| stack | rand_core | digest / sha2 / hmac / hkdf | dalek | who forces it on us |
|---|---|---|---|---|
| **new** (use for everything we write) | **0.10** | digest **0.11**, sha2 **0.11**, hmac **0.13**, hkdf **0.13**, sha3 **0.12** | ed25519-dalek **3.0.0**, x25519-dalek **3.0.0**, curve25519-dalek **5.0.0** | our own code; argon2 0.6; blake3 1.8 (`digest` opt) |
| **old** (transitive only) | 0.6 (+ rand 0.8) | digest 0.10, sha2 0.10, hmac 0.12, hkdf 0.12, sha3 0.10 | ed25519-dalek 2.2, x25519-dalek 2.0, curve25519-dalek 4.1 | **opaque-ke 4.0.1** (argon2 **0.5**, rand 0.8, voprf 0.5) and **Arti 0.45** (`tor-llcrypto`) |

Verified-to-resolve `Cargo.toml` (probe built and ran green on this VM, §14):

```toml
[dependencies]
# ---- new stack (rand_core 0.10 / digest 0.11) ----
ed25519-dalek    = { version = "=3.0.0", features = ["rand_core", "pkcs8", "alloc", "serde", "digest"] }
x25519-dalek     = { version = "=3.0.0", features = ["static_secrets", "getrandom"] }
curve25519-dalek = "=5.0.0"            # only if you touch points/scalars directly
ed25519          = { version = "=3.0.0", features = ["pkcs8", "alloc"] }  # Signature type, re-exported by dalek
signature        = "=3.0.0"            # Signer/Verifier traits, re-exported by dalek
sha2             = "=0.11.0"
sha3             = "=0.12.0"           # Sha3_256 for the .onion checksum (if not using tor-hscrypto)
hmac             = "=0.13.0"
hkdf             = "=0.13.0"
digest           = "0.11"              # 0.11.3 resolves; needed only for `digest::Output` / trait names
argon2           = { version = "=0.6.0", features = ["password-hash", "zeroize"] }  # unattended-access password
rand             = "=0.10.2"
rand_core        = "=0.10.1"
getrandom        = { version = "=0.4.3", features = ["sys_rng"] }  # SysRng + getrandom::fill
zeroize          = { version = "=1.9.0", features = ["derive"] }
subtle           = "=2.6.1"            # ConstantTimeEq — preferred ct-compare
blake3           = { version = "=1.8.7", features = ["zeroize"] } # optional: file-transfer hashing, derive_key
data-encoding    = "=2.11.1"           # BASE32_NOPAD for .onion
# ---- OPAQUE (old stack; pulls rand 0.8 / argon2 0.5 / curve25519-dalek 4 transitively) ----
opaque-ke        = { version = "=4.0.1", default-features = false, features = ["argon2", "ristretto255", "serde"] }
sha2_010         = { package = "sha2", version = "0.10" }  # KeyExchange hash for opaque-ke must be digest-0.10 based
rand_core_06     = { package = "rand_core", version = "0.6" }  # for the RNG adapter (§3.4)
# ---- Arti types for onion addresses (already in the tree via arti-client) ----
tor-hscrypto     = "=0.45.0"           # HsId: FromStr + DisplayRedacted for "<56 base32>.onion"
safelog          = "0.9"               # DisplayRedacted trait (HsId has no plain Display)
```

Key facts (all verified below):
- `ed25519-dalek 3.0.0` / `x25519-dalek 3.0.0` / `curve25519-dalek 5.0.0` (all released
  2026-07-06) depend on **`rand_core = "0.10"`**; `SigningKey::generate<R: CryptoRng + ?Sized>(&mut R)`
  where `CryptoRng` is **rand_core 0.10's** alias for `TryCryptoRng<Error = Infallible>` (§3, §4).
- `rand 0.10`: `rand::rng()` returns `ThreadRng` which *is* a `rand_core::CryptoRng`, so
  `SigningKey::generate(&mut rand::rng())` compiles. `RngCore`→`Rng`, `TryRngCore`→`TryRng`
  (renamed; deprecated stubs remain). `OsRng` is gone: use `getrandom::SysRng` (fallible) wrapped
  in `rand_core::UnwrapErr(SysRng)` (§3).
- `opaque-ke 4.0.1` is **still on the old stack**: `argon2 = "0.5"`, `rand = "0.8"`, `digest 0.10`,
  `hkdf/hmac 0.12`, `curve25519-dalek 4`, `voprf 0.5` (rand_core 0.6). It **does not conflict**
  with `argon2 0.6` (different majors coexist), but the `Ksf` impl is for **`argon2 0.5`'s**
  `Argon2` type, which opaque-ke re-exports as `opaque_ke::argon2` — use that in the
  `CipherSuite` and never mix it with the 0.6 type (§8). Its RNG parameter is
  rand 0.8's `CryptoRng + RngCore` (rand_core 0.6) → tiny adapter in §3.4 (same trick Arti uses).
- `opaque-ke 4.1.0-pre.2` (2026-03-27) is still argon2 0.5 / rand 0.8; only its new `kem`
  feature touches rand_core 0.10. Nothing newer exists. Stay on 4.0.1.
- Onion v3 address: `tor-hscrypto::pk::HsId` already implements `FromStr` (validates
  version+checksum) and `safelog::DisplayRedacted` (`display_unredacted()`), and `From<[u8;32]>`
  / `Into<[u8;32]>`. Reuse it; a 20-line stand-alone implementation is also given and was
  verified byte-identical against `HsId` and against the public DuckDuckGo address (§9).
- Nothing here needs cmake, nasm, bindgen/libclang, or system libraries. `blake3` compiles
  `.S` files via `cc` (gcc/clang as assembler; MASM on MSVC) — worked on this VM (§11).

---

## 1. Versions (crates.io, queried 2026-08-28)

| crate | latest stable | published | MSRV | source |
|---|---|---|---|---|
| ed25519-dalek | **3.0.0** | 2026-07-06 | 1.85 | https://crates.io/api/v1/crates/ed25519-dalek |
| x25519-dalek | **3.0.0** | 2026-07-06 | 1.85 | https://crates.io/api/v1/crates/x25519-dalek |
| curve25519-dalek | **5.0.0** | 2026-07-06 | 1.85 | https://crates.io/api/v1/crates/curve25519-dalek |
| ed25519 | **3.0.0** | 2026-05-03 | 1.85 | https://crates.io/api/v1/crates/ed25519 |
| signature | **3.0.0** | 2026-05-02 | 1.85 | https://crates.io/api/v1/crates/signature |
| digest | **0.11.3** (0.11.0/0.11.1 yanked) | 2026-05-03 | 1.85 | https://crates.io/api/v1/crates/digest |
| sha2 | **0.11.0** | 2026-03-25 | 1.85 | https://crates.io/api/v1/crates/sha2 |
| sha3 | **0.12.0** (0.11.0 on 2026-04-02) | 2026-05-15 | 1.85 | https://crates.io/api/v1/crates/sha3 |
| hmac | **0.13.0** | 2026-03-29 | 1.85 | https://crates.io/api/v1/crates/hmac |
| hkdf | **0.13.0** | 2026-03-30 | 1.85 | https://crates.io/api/v1/crates/hkdf |
| argon2 | **0.6.0** | **2026-08-27** (yesterday) | 1.85 | https://crates.io/api/v1/crates/argon2 |
| password-hash | 0.6.1 | 2026-04-08 | 1.85 | https://crates.io/api/v1/crates/password-hash |
| opaque-ke | **4.0.1** (4.1.0-pre.2 is a pre-release) | 2025-11-03 | 1.85 | https://crates.io/api/v1/crates/opaque-ke |
| voprf | 0.5.0 (0.6.0-pre.1 pre-release) | 2024-03-07 | 1.65 | https://crates.io/api/v1/crates/voprf |
| rand | **0.10.2** | 2026-07-02 | 1.85 | https://crates.io/api/v1/crates/rand |
| rand_core | **0.10.1** | 2026-04-13 | 1.85 | https://crates.io/api/v1/crates/rand_core |
| rand_chacha | 0.10.0 | 2026-02-02 | 1.85 | https://crates.io/api/v1/crates/rand_chacha |
| getrandom | **0.4.3** | 2026-06-17 | 1.85 | https://crates.io/api/v1/crates/getrandom |
| zeroize | **1.9.0** | 2026-06-12 | 1.85 | https://crates.io/api/v1/crates/zeroize |
| subtle | 2.6.1 | 2024-06-24 | — | https://crates.io/api/v1/crates/subtle |
| blake3 | **1.8.7** | 2026-08-20 | — | https://crates.io/api/v1/crates/blake3 |
| data-encoding | **2.11.1** | 2026-08-03 | 1.48 | https://crates.io/api/v1/crates/data-encoding |
| constant_time_eq | 0.5.0 (**MSRV 1.95**) / 0.4.2 (1.85) | 2026-04-20 | 1.95 | https://crates.io/api/v1/crates/constant_time_eq |
| pkcs8 / spki / der | 0.11.0 / 0.8.0 / 0.8.1 | — | — | crates.io (transitive via `ed25519 3`) |

Note `rand`'s crates.io "newest_version" is 0.8.8 (a 0.8 maintenance release from 2026-08-25);
`max_stable_version` is 0.10.2. Do not let that confuse `cargo add`.

---

## 2. Dependency alignment (what unifies with what)

From the extracted `Cargo.toml`s:

| crate | depends on | path |
|---|---|---|
| ed25519-dalek 3.0.0 | `curve25519-dalek = "5.0.0"` (features `digest`), `ed25519 = "3"`, `sha2 = "0.11"`, `signature = "3"` (opt), `rand_core = "0.10"` (opt), `zeroize = "1.5"` (opt), `serde = "1"` (opt), `subtle = "2.3"` | `ed25519-dalek-3.0.0/Cargo.toml` `[dependencies.*]` |
| x25519-dalek 3.0.0 | `curve25519-dalek = "5.0.0"`, `rand_core = "0.10"` (always), `getrandom = "0.4"` (opt), `zeroize`, `serde` (opt) | `x25519-dalek-3.0.0/Cargo.toml` |
| curve25519-dalek 5.0.0 | `digest = "0.11"` (opt), `rand_core = "0.10"` (opt), `subtle = "2.6.0"` (`const-generics`), `zeroize`, `cpufeatures 0.3`, `curve25519-dalek-derive 0.1` (x86_64), `fiat-crypto` (opt backend); build-dep `rustc_version` | `curve25519-dalek-5.0.0/Cargo.toml` |
| ed25519 3.0.0 | `signature = "3"`, `pkcs8 = "0.11"` (opt), `serdect = "0.4"` (opt) | `ed25519-3.0.0/Cargo.toml` |
| signature 3.0.0 | `digest = "0.11"` (opt), `rand_core = "0.10"` (opt) | `signature-3.0.0/Cargo.toml` |
| sha2 0.11.0 | `digest = "0.11"`, `cpufeatures 0.3` | `sha2-0.11.0/Cargo.toml` |
| hmac 0.13.0 | `digest = "0.11.2"` (feature `mac`) | `hmac-0.13.0/Cargo.toml` |
| hkdf 0.13.0 | `hmac = "0.13"`, `kdf = "0.1"` (opt) | `hkdf-0.13.0/Cargo.toml` |
| sha3 0.12.0 | `digest = "0.11"`, `keccak = "0.2"`, `sponge-cursor = "0.1"` | `sha3-0.12.0/Cargo.toml` |
| digest 0.11.3 | `crypto-common = "0.2"` (renamed `common`), `block-buffer = "0.12"` (opt `block-api`, default), `const-oid 0.10` (opt), `ctutils 0.4` (opt, `mac`), `zeroize 1.7` (opt) | `digest-0.11.3/Cargo.toml` |
| argon2 0.6.0 | `blake2 = "0.11"`, `base64ct = "1.7"`, `password-hash = "0.6"` (opt, feature `phc`), `kdf 0.1` (opt), `rayon` (opt `parallel`), `zeroize` (opt), `cpufeatures 0.3` | `argon2-0.6.0/Cargo.toml` |
| password-hash 0.6.1 | `getrandom = "0.4"` (opt), `rand_core = "0.10"` (opt), `phc = "0.6"` (opt) | `password-hash-0.6.1/Cargo.toml` |
| rand 0.10.2 | `rand_core = "0.10.0"`, `getrandom = "0.4.0"` (opt `sys_rng`), `chacha20 = "0.10"` (opt `std_rng`, feature `rng`) | `rand-0.10.2/Cargo.toml` |
| getrandom 0.4.3 | `rand_core = "0.10.0"` (optional; feature `sys_rng = ["dep:rand_core"]` turns it on and exposes `SysRng`); features `std`, `wasm_js` | `getrandom-0.4.3/Cargo.toml` `[features]` |
| blake3 1.8.7 | `constant_time_eq = "0.4.2"`, `arrayvec`, `digest = "0.11.2"` (opt `digest`/`traits-preview`), `zeroize` (opt), `cc` (build) | `blake3-1.8.7/Cargo.toml` |
| **opaque-ke 4.0.1** | **`argon2 = "0.5"`** (opt, `alloc`), **`curve25519-dalek = "4"`** (opt), **`ed25519-dalek = "2"`** (opt), **`digest = "0.10"`**, `elliptic-curve = "0.13"`, **`generic-array = "=0.14.7"`**, **`hkdf = "0.12"`**, **`hmac = "0.12"`**, **`rand = "0.8"`** (default-features=false), `subtle = "2.6"`, **`voprf = "0.5"`**, `zeroize = "1.8"`, `derive-where 1.4`, `serde` (opt) | `opaque-ke-4.0.1/Cargo.toml` |
| opaque-ke 4.1.0-pre.2 | same as above + `ml-kem 0.3.0-rc.0` and `rand_core 0.10` **only under the `kem` feature**; MSRV 1.87 | `opaque-ke-4.1.0-pre.2/Cargo.toml` |
| voprf 0.5.0 | `curve25519-dalek = "4"`, `digest 0.10`, `rand_core = "0.6"`, `generic-array 0.14`, `sha2 0.10` (opt) | `voprf-0.5.0/Cargo.toml` |
| voprf 0.6.0-pre.1 | `curve25519-dalek 4`, `rand_core = "0.9"`, `generic-array = "1"` — still not the new stack | `voprf-0.6.0-pre.1/Cargo.toml` |
| tor-llcrypto 0.45.0 (Arti) | `ed25519-dalek = "2.2"`, `curve25519-dalek = "4.1"`, `x25519-dalek = "2.0.0"`, `digest 0.10`, `sha2 0.10`, `sha3 0.10.6`, `rand_core = "0.10.1"` **and** `rand_core_06 = { package = "rand_core", version = "0.6" }` | `tor-llcrypto-0.45.0/Cargo.toml` lines 113–212 |

Resulting duplicates in the probe lockfile (`cargo tree -d` in `/tmp/probe-crypto`): argon2
0.5.3+0.6.0, blake2 0.10.6+0.11.0, block-buffer 0.10.4+0.12.1, const-oid 0.9.6+0.10.2,
constant_time_eq 0.4.2+0.5.0, cpufeatures 0.2.17+0.3.1, crypto-common 0.1.7+0.2.2,
curve25519-dalek 4.1.3+5.0.0, der 0.7.10+0.8.1, digest 0.10.7+0.11.3, ed25519 2.2.3+3.0.0,
ed25519-dalek 2.2.0+3.0.0, getrandom 0.2.17+0.4.3, hkdf 0.12.4+0.13.0, hmac 0.12.1+0.13.0,
keccak 0.1.6+0.2.2, password-hash 0.5.0+0.6.1, pkcs8 0.10.2+0.11.0, rand 0.8.8+0.10.2,
rand_chacha 0.3.1+0.10.0, rand_core 0.6.4+0.10.1, serdect 0.2.0+0.4.3, sha2 0.10.9+0.11.0,
sha3 0.10.9+0.12.0, signature 2.2.0+3.0.0, spki 0.7.3+0.8.0, x25519-dalek 2.0.1+3.0.0.
All of the old-stack copies are pulled by `opaque-ke` and/or `tor-llcrypto` (`cargo tree -i`
output in §14). This is exactly the situation Arti itself lives with
(`tor-llcrypto-0.45.0/src/util/rng.rs` lines 1–10: "We need this (for now) for compatibility
with *-dalek and some other crypto libraries").

**Consequence for key types:** `tor_llcrypto::pk::ed25519::PublicKey` wraps
`ed25519_dalek 2::VerifyingKey` (`tor-llcrypto-0.45.0/src/pk/ed25519.rs` line 53) and
`tor_hscrypto::pk::HsId` is `[u8; 32]` (`tor-hscrypto-0.45.0/src/pk.rs` line 46). Convert
between Arti and our dalek-3 types **through bytes only** (`to_bytes()` / `from_bytes()`),
never via `From` impls. The probe does `HsId::from(vk.to_bytes())` and
`let back: [u8; 32] = hsid.into()` (both exist: `define_bytes!` macro, `pk.rs` lines 31–47).

---

## 3. Randomness: rand 0.10 / rand_core 0.10 / getrandom 0.4

### 3.1 Trait names (rand_core 0.10.1, `rand_core-0.10.1/src/lib.rs`)

```rust
pub trait TryRng { type Error: core::error::Error; fn try_next_u32(..); fn try_next_u64(..); fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error>; }   // line 189
pub trait Rng: TryRng<Error = Infallible> { fn next_u32(&mut self) -> u32; fn next_u64(&mut self) -> u64; fn fill_bytes(&mut self, dst: &mut [u8]); } // line 49; blanket impl for every TryRng<Error=Infallible>
pub trait TryCryptoRng: TryRng {}                                              // line 249 (marker)
pub trait CryptoRng: Rng + TryCryptoRng<Error = Infallible> {}                 // line 95; blanket impl line 97
#[deprecated(since = "0.10.0", note = "use `Rng` instead")]    pub trait RngCore: Rng {}      // line 257
#[deprecated(since = "0.10.0", note = "use `TryRng` instead")] pub trait TryRngCore: TryRng {} // line 265
pub struct UnwrapErr<R: TryRng>(pub R);   // src/unwrap_err.rs line 30; impls TryRng<Error=Infallible> and TryCryptoRng (line 55)
```
CHANGELOG 0.10.0 (`rand_core-0.10.1/CHANGELOG.md`): "`RngCore` and `TryRngCore` are renamed
to `Rng` and `TryRng`"; removed `OsRng`, `OsError`, `os_rng` feature, `getrandom` dependency,
`SeedableRng::from_os_rng`; `Rng::unwrap_err` removed "in favor of explicit wrapping in
`UnwrapErr`". `TryRng`/`TryCryptoRng` have blanket impls through `DerefMut` (lines 205, 251),
so `&mut R` works wherever `R` does.

### 3.2 rand 0.10.2 surface (`rand-0.10.2/src/lib.rs`, `src/rng.rs`, `src/rngs/`)

```rust
pub use rand_core::{CryptoRng, Rng, SeedableRng, TryCryptoRng, TryRng};   // lib.rs line 59
pub use crate::rngs::thread::rng;        // lib.rs 70  -> `rand::rng() -> ThreadRng`   (thread.rs 201)
pub use rng::{Fill, RngExt};             // lib.rs 72  -> RngExt: random(), random_range(), random_bool(), fill(), sample() (rng.rs 56–330)
pub fn random<T>() -> T                  // lib.rs 190 (thread_rng feature)
pub fn fill<T: Fill>(dest: &mut [T])     // lib.rs 314
// rngs (rngs/mod.rs 106–119): SmallRng, StdRng (ChaCha12 via `chacha20` crate), ThreadRng,
//   `pub use chacha20::{ChaCha8Rng, ChaCha12Rng, ChaCha20Rng}` (feature `chacha`),
//   `pub use getrandom::{Error as SysError, SysRng}` (feature `sys_rng`)
```
`ThreadRng`: `impl TryRng for ThreadRng { type Error = Infallible; .. }` and
`impl TryCryptoRng for ThreadRng {}` (`rngs/thread.rs` 212–241) → it satisfies the
`CryptoRng` bound used by dalek 3. `StdRng` also `TryCryptoRng` (`rngs/std.rs` 104).
CHANGELOG 0.10.0 (`rand-0.10.2/CHANGELOG.md` 34–48): "Rename `os_rng` -> `sys_rng`, `OsRng` ->
`SysRng`, `OsError` -> `SysError`"; "Rename `Rng` -> `RngExt` as upstream `rand_core` has
renamed `RngCore` -> `Rng`". (0.9 already renamed `thread_rng()` → `rng()`, `gen` → `random`,
`gen_range` → `random_range`, `distributions` → `distr`.) There is **no `random_bytes` fn**;
use `rand::random::<[u8; 32]>()` or `Rng::fill_bytes`.

### 3.3 getrandom 0.4.3 (`getrandom-0.4.3/src/lib.rs`, `src/sys_rng.rs`)

```rust
pub fn fill(dest: &mut [u8]) -> Result<(), Error>;      // lib.rs 87
pub fn u32() -> Result<u32, Error>; pub fn u64() -> Result<u64, Error>;  // 143, 157
pub struct SysRng;   // sys_rng.rs 34; impl TryRng (36) + TryCryptoRng (55); NOT infallible
pub use rand_core;   // lib.rs 32 (re-export, so `getrandom::rand_core::UnwrapErr` works)
```
Feature `sys_rng` (=dep `rand_core`) is required for `SysRng` — it's what rand's `sys_rng`
feature turns on (`rand-0.10.2/Cargo.toml` `sys_rng = ["dep:getrandom", "getrandom/sys_rng"]`).

Verified snippet (probe `main.rs`, ran OK):
```rust
let mut rng = rand::rng();                                   // ThreadRng: CryptoRng
let mut token = [0u8; 32];
rand_core::Rng::fill_bytes(&mut rng, &mut token);            // or `use rand::Rng;`
let token2: [u8; 32] = rand::random();
let mut sys = rand_core::UnwrapErr(getrandom::SysRng);       // infallible view of the OS RNG
rand_core::Rng::fill_bytes(&mut sys, &mut token);
getrandom::fill(&mut token).unwrap();                        // no rand at all
let mut chacha = <rand_chacha::ChaCha20Rng as rand_core::SeedableRng>::from_seed([7u8; 32]);
```
Recommendation: use `rand::rng()` for keys/tokens (it is a reseeding ChaCha12 fed from
`SysRng`, `rngs/mod.rs` 18–22) or `UnwrapErr(SysRng)` when you want a stateless OS-RNG.
`rand_chacha 0.10` is only needed for deterministic test RNGs; rand 0.10's own `StdRng`
is now backed by the `chacha20` crate, not `rand_chacha`.

### 3.4 Adapter: feeding a rand_core-0.10 RNG to old-stack APIs (opaque-ke 4.0.1, dalek 2)

Arti does exactly this internally (`tor-llcrypto-0.45.0/src/util/rng.rs` lines 12–48,
`RngCompat<R>`; used by `Keypair::generate`, `src/pk/ed25519.rs` 90–93). Copy of the pattern,
verified in the probe:
```rust
// Cargo: rand_core_06 = { package = "rand_core", version = "0.6" }
struct Rng06<R>(R);
impl<R: rand_core::CryptoRng> rand_core_06::RngCore for Rng06<R> {
    fn next_u32(&mut self) -> u32 { rand_core::Rng::next_u32(&mut self.0) }
    fn next_u64(&mut self) -> u64 { rand_core::Rng::next_u64(&mut self.0) }
    fn fill_bytes(&mut self, dest: &mut [u8]) { rand_core::Rng::fill_bytes(&mut self.0, dest) }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_06::Error> {
        rand_core::Rng::fill_bytes(&mut self.0, dest); Ok(())
    }
}
impl<R: rand_core::CryptoRng> rand_core_06::CryptoRng for Rng06<R> {}
// usage: let mut crng = Rng06(::rand::rng());  ClientLogin::<CS>::start(&mut crng, pw)
```
Alternative with zero adapter code: `rand_08 = { package = "rand", version = "0.8", features = ["std", "std_rng"] }`
and `rand_08::rngs::OsRng` (the probe used both). Note opaque-ke declares `rand 0.8` with
`default-features = false`, so `OsRng` only exists if *someone* enables rand 0.8's `std`/`getrandom`.

---

## 4. ed25519-dalek 3.0.0

Features (`ed25519-dalek-3.0.0/Cargo.toml` `[features]`, README table):
`default = ["fast", "zeroize"]`; `rand_core` (enables `SigningKey::generate`); `pkcs8`
(`ed25519/pkcs8`); **`alloc` is required for `EncodePrivateKey`/`EncodePublicKey`
(`to_pkcs8_der`, `to_public_key_der`)** — the probe failed with "no method named
`to_pkcs8_der`" until `alloc` was added (`signing.rs` line 728: `#[cfg(all(feature = "alloc",
feature = "pkcs8"))]`); `pem` (=alloc+pkcs8+pem); `serde` (via `serdect`, hex in human-readable
formats, bytes in binary); `digest` (Ed25519ph `Context`, `sign_prehashed`); `batch`;
`hazmat` (raw sign with `ExpandedSecretKey`, `hazmat.rs` 40–242); `legacy_compatibility`
(unsafe, do not enable).

Breaking changes 3.0.0 (`CHANGELOG.md`): edition 2024, MSRV 1.85, `std` feature removed,
`ed25519 3`, `signature 3`, `sha2`/`sha3 0.11`, `getrandom 0.4`, `rand_core 0.10`; re-exports
`rand_core`; new `MultipartSigner/Verifier` impls; `KeySizeUser`/`TryKeyInit`/`Generate` under
`digest`.

API (`src/signing.rs`, `src/verifying.rs`, `src/lib.rs`, `src/constants.rs`):
```rust
pub const SECRET_KEY_LENGTH: usize = 32; PUBLIC_KEY_LENGTH = 32; SIGNATURE_LENGTH = 64; KEYPAIR_LENGTH = 64;
pub use ed25519::Signature; pub use ed25519::signature::{Signer, Verifier}; pub use rand_core; pub use ed25519::pkcs8; pub use sha2::Sha512;
impl SigningKey {
    pub fn generate<R: CryptoRng + ?Sized>(csprng: &mut R) -> SigningKey   // signing.rs 213 (feature rand_core); body: fill_bytes(&mut secret)
    pub fn from_bytes(secret_key: &SecretKey /*[u8;32]*/) -> Self          // 115
    pub fn to_bytes(&self) -> SecretKey                                    // 125
    pub fn from_keypair_bytes(bytes: &[u8; 64]) -> Result<SigningKey, SignatureError>  // 149
    pub fn to_keypair_bytes(&self) -> [u8; KEYPAIR_LENGTH]                 // 171
    pub fn verifying_key(&self) -> VerifyingKey                            // 180
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), SignatureError>          // 337
    pub fn verify_strict(&self, ..)                                        // 485
    pub fn to_scalar_bytes(&self) -> [u8; 32]; pub fn to_scalar(&self) -> Scalar   // 521, 547
}
impl Signer<Signature> for SigningKey        // 598 -> sk.sign(msg) / sk.try_sign(msg)
impl KeypairRef for SigningKey               // 594 (signature::Keypair)
impl VerifyingKey {
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<VerifyingKey, SignatureError>  // verifying.rs 175 (rejects non-canonical / off-curve)
    pub fn to_bytes(&self) -> [u8; 32]; pub fn as_bytes(&self) -> &[u8; 32]      // 130, 136
    pub fn is_weak(&self) -> bool                                                 // 200 (small-order check)
    pub fn verify_strict(&self, message: &[u8], signature: &Signature) -> Result<(), SignatureError> // 367
    pub fn to_montgomery(&self) -> MontgomeryPoint                                // 484
}
impl Verifier<ed25519::Signature> for VerifyingKey   // 567
```
pkcs8: `impl pkcs8::EncodePrivateKey for SigningKey` (728), `TryFrom<pkcs8::KeypairBytes>`
(736/745), `TryFrom<PrivateKeyInfoRef>` (791); `DecodePrivateKey`/`DecodePublicKey` come
from `pkcs8` blanket impls. Doc examples in the crate use
`getrandom::{SysRng, rand_core::{TryRng, UnwrapErr}}` (`signing.rs` 201, 253, 298).

Verified snippet (probe):
```rust
use ed25519_dalek::{Signer, Verifier, SigningKey, VerifyingKey, Signature};
use ed25519_dalek::pkcs8::{EncodePrivateKey, DecodePrivateKey, EncodePublicKey, DecodePublicKey};
let sk = SigningKey::generate(&mut rand::rng());          // or &mut rand_core::UnwrapErr(getrandom::SysRng)
let vk = sk.verifying_key();
let sig: Signature = sk.sign(transcript_hash);
vk.verify_strict(transcript_hash, &sig)?;                  // use verify_strict for peer signatures
let vk2 = VerifyingKey::from_bytes(&vk.to_bytes())?;       // wire format: 32 bytes
let sig2 = Signature::from_bytes(&sig.to_bytes());          // 64 bytes; from_bytes is infallible
let der = sk.to_pkcs8_der()?;                               // 83 bytes (v2 PKCS#8 incl. public key)
let sk3 = SigningKey::from_pkcs8_der(der.as_bytes())?;
let spki = vk.to_public_key_der()?;                         // 44 bytes SPKI
let vk3 = VerifyingKey::from_public_key_der(spki.as_bytes())?;
// serde -> CBOR (ciborium): VerifyingKey = 34 bytes, Signature = 66 bytes (byte-string encoding)
```
Measured in probe: PKCS#8 DER 83 B, SPKI DER 44 B, CBOR(VerifyingKey) 34 B, CBOR(Signature) 66 B.

Signing with the **onion identity key** (host identity, plan §B.6): that key lives in Arti's
keystore as `tor_hscrypto::pk::HsIdKeypair(ed25519::ExpandedKeypair)` (`pk.rs` 65–77, stored
in *expanded* (a, r) form, so it can't be turned into a dalek `SigningKey`). Use
`tor_llcrypto::pk::ed25519::ExpandedKeypair::sign(&self, message) -> Signature`
(`tor-llcrypto-0.45.0/src/pk/ed25519.rs` 192) and `to_secret_key_bytes()/from_secret_key_bytes([u8;64])`
(206, 219). Verification on the client side is plain ed25519 with dalek 3 `VerifyingKey`
(the signature is standard). If you'd rather keep it dalek-3-only, `ed25519_dalek::hazmat::{ExpandedSecretKey::from_bytes(&[u8;64]), raw_sign::<Sha512>(..)}` (feature `hazmat`,
`hazmat.rs` 84, 137) accept the same 64-byte expanded form.

---

## 5. x25519-dalek 3.0.0

`x25519-dalek-3.0.0/src/x25519.rs`:
```rust
pub struct PublicKey(MontgomeryPoint);  impl From<[u8;32]>; to_bytes(); as_bytes(); AsRef<[u8]>   // 32–55
pub struct EphemeralSecret; fn diffie_hellman(self, &PublicKey) -> SharedSecret (83); random_from_rng<R: CryptoRng + ?Sized>(&mut R) (88); random() [feature getrandom] (97); ZeroizeOnDrop
pub struct ReusableSecret  (feature reusable_secrets): diffie_hellman(&self) (148), random_from_rng (153), random (162)
pub struct StaticSecret    (feature static_secrets): diffie_hellman(&self) (212), random_from_rng (217), random (226), to_bytes (235), as_bytes (241), From<[u8;32]> (247)
pub struct SharedSecret: to_bytes/as_bytes (291/297), was_contributory() (335)   // check it! rejects all-zero output
pub fn x25519(k: [u8; 32], u: [u8; 32]) -> [u8; 32]   // 390 raw RFC 7748
```
CHANGELOG 3.0.0: `Zeroize` impls removed (secrets are zeroized on drop only), `alloc` feature
removed, deprecated `::new()` constructors removed, rand_core 0.10. `random()` calls
`getrandom::fill` (feature `getrandom`, `x25519.rs` 97–103).
Probe: `StaticSecret::random_from_rng(&mut rng)`, `EphemeralSecret::random()`, DH both ways
equal, `was_contributory()` true.

---

## 6. Hashing / MAC / KDF on digest 0.11

digest 0.11 (`digest-0.11.3/CHANGELOG.md`): `generic-array` → **`hybrid-array`**
(`Output<D>` is now `hybrid_array::Array<u8, N>`; `impl From<Array<T,U>> for [T; N]` exists,
`hybrid-array-0.4.14/src/lib.rs` 757, plus `Deref<Target=[T]>` 718, so `let h: [u8; 32] =
Sha256::digest(x).into();` and `&h[..]` both work), `digest::core_api` → `digest::block_api`,
crypto-common 0.2. **digest 0.11.0 and 0.11.1 are yanked; 0.11.2+ required** (hmac pins
`digest = "0.11.2"`).

`Digest` trait (`digest-0.11.3/src/digest.rs` 17–56): `new()`, `new_with_prefix()`, `update()`,
`chain_update()`, `finalize()`, `finalize_into()`, `finalize_reset()`, `reset()`,
`output_size()`, `digest(data)`. Unchanged names from 0.10.
`Mac` trait (`src/mac.rs` 15–81): `update`, `chain_update`, `finalize() -> CtOutput`,
`finalize_reset`, `verify(&Output)`, `verify_slice(&[u8])`, `verify_truncated_left/right`.
`KeyInit::new_from_slice` comes from `crypto-common` (`digest::KeyInit`, `lib.rs` 70).

sha2 0.11 (`sha2-0.11.0/CHANGELOG.md`): type aliases replaced by newtypes (`Sha256`, `Sha512`
are structs now — irrelevant unless you named `CoreWrapper<..>`), `asm`/`std`/`soft` features
removed, backend chosen via cfg flags. `pub use digest::{self, Digest}` (`src/lib.rs` 19).
hmac 0.13 (`hmac-0.13.0/CHANGELOG.md`): newtypes `Hmac<D>`, `HmacReset<D>`, `SimpleHmac<D>`;
`std`/`reset` features removed; `pub use digest::{self, KeyInit, Mac, block_api::EagerHash}`
(`src/lib.rs` 20).
hkdf 0.13 (`hkdf-0.13.0/CHANGELOG.md`, `src/lib.rs` 25–32, 94–174): `Hkdf<H>` is now a type
alias for `GenericHkdf<Hmac<H>>`; `Hkdf::<H>::new(salt: Option<&[u8]>, ikm: &[u8])`,
`extract(salt, ikm) -> (Output<H>, Self)`, `from_prk(&[u8]) -> Result<Self, InvalidPrkLength>`,
`expand(&self, info: &[u8], okm: &mut [u8]) -> Result<(), InvalidLength>`,
`expand_multi_info(&self, info_components: &[&[u8]], okm) `; `HkdfExtract<H>` streaming
extract (`new(salt)`, `input_ikm`, `finalize`). `expand` errors if `okm.len() > 255 * HashLen`.
sha3 0.12 (`sha3-0.12.0/CHANGELOG.md`): `Sha3_256` etc. are newtypes; `Shake128/256` moved to
the `shake` crate in 0.12 (0.11 moved cSHAKE/TurboSHAKE out). Only `Sha3_256` needed here.

Verified snippet (probe):
```rust
use sha2::{Sha256, Sha512, Digest};
let th = Sha256::new().chain_update(b"HELLO").chain_update(b"SESSION_ACCEPT").finalize(); // Output<Sha256>
let th_arr: [u8; 32] = th.into();                       // hybrid-array -> fixed array
use hmac::{Hmac, KeyInit, Mac};
let mut mac = Hmac::<Sha256>::new_from_slice(&session_token)?;   // any key length
mac.update(&th); let tag = mac.finalize().into_bytes();
Hmac::<Sha256>::new_from_slice(&session_token)?.chain_update(&th).verify_slice(&tag)?;   // ct compare
use hkdf::Hkdf;
let hk = Hkdf::<Sha256>::new(Some(&th_arr), shared_secret.as_bytes());   // salt = transcript hash
let mut okm = [0u8; 32]; hk.expand(b"tornect v1 sas", &mut okm)?;
let (prk, hk2) = Hkdf::<Sha512>::extract(None, ikm); hk2.expand_multi_info(&[b"tornect", b"v1", b"session"], &mut okm64)?;
let sas = u32::from_be_bytes(okm[..4].try_into().unwrap()) % 1_000_000;   // 6-digit SAS
```
blake3 1.8.7 (`blake3-1.8.7/src/lib.rs` via README): `blake3::hash(&[u8]) -> Hash`,
`Hasher::new()/new_keyed(&[u8;32])/new_derive_key(ctx)`, `update`, `finalize`,
`blake3::derive_key(context: &str, key_material: &[u8]) -> [u8; 32]`, `Hash::as_bytes()`;
`Hash` compares in constant time (uses `constant_time_eq`). Features: `rayon`, `mmap`,
`zeroize`, `digest`/`traits-preview` (digest 0.11.2), `pure`, `neon`, `no_avx512`… Only useful
for file-transfer integrity / fast keyed hashing; not needed for the handshake.

---

## 7. argon2 0.6.0 (unattended-access password)

Released 2026-08-27 (`argon2-0.6.0/CHANGELOG.md`): edition 2024 / MSRV 1.85; feature `simple`
renamed **`password-hash`**; `std` feature removed; `password-hash 0.6`, `blake2 0.11`,
`cpufeatures 0.3`; new `parallel` feature (rayon); `kdf::{Kdf, Pbkdf}` impls; allocation
failures detected in `hash_password_into`. Features (`Cargo.toml`):
`default = ["alloc", "getrandom", "password-hash"]`, `zeroize`, `rand_core`, `parallel`, `kdf`.

API (`argon2-0.6.0/src/lib.rs`, `src/params.rs`, `src/algorithm.rs`, `src/version.rs`):
```rust
pub enum Algorithm { Argon2d = 0, Argon2i = 1, Argon2id = 2 }     // algorithm.rs 26–48; Default = Argon2id
pub enum Version { V0x10 = 0x10, V0x13 = 0x13 }                   // version.rs 8–18; Default = V0x13 (v19)
impl Params {
    pub const DEFAULT_M_COST: u32 = 19 * 1024;  // KiB  (params.rs 48)  — OWASP "19 MiB, t=2, p=1"
    pub const DEFAULT_T_COST: u32 = 2;          // 58
    pub const DEFAULT_P_COST: u32 = 1;          // 67
    pub const DEFAULT_OUTPUT_LEN: usize = 32;   // 82; MIN_OUTPUT_LEN = 4
    pub const MIN_M_COST: u32 = 8;              // 52 (2*SYNC_POINTS); must also be >= 8*p_cost
    pub const fn new(m_cost: u32, t_cost: u32, p_cost: u32, output_len: Option<usize>) -> Result<Self>  // 123
}
pub struct ParamsBuilder; .m_cost() .t_cost() .p_cost() .output_len() .build()   // 504–604
impl Argon2<'key> {
    pub fn new(algorithm: Algorithm, version: Version, params: Params) -> Self                   // lib.rs 241
    pub fn new_with_secret(secret: &'key [u8], algorithm, version, params) -> Result<Self>       // 256 (pepper)
    pub fn hash_password_into(&self, pwd: &[u8], salt: &[u8], out: &mut [u8]) -> Result<()>      // 285 (feature alloc)
    pub fn hash_password_into_with_memory(&self, pwd, salt, out, memory_blocks: &mut [Block])     // 307 (no_std path)
}
pub const MIN_SALT_LEN: usize = 8; RECOMMENDED_SALT_LEN = 16;   // lib.rs 176, 182
// with feature password-hash:
pub use password_hash::{self, CustomizedPasswordHasher, PasswordHasher, PasswordVerifier, phc::PasswordHash};
```
password-hash 0.6.1 (`password-hash-0.6.1/src/lib.rs` 95–240): `PasswordHasher::hash_password(&self, password: &[u8]) -> Result<H>`
(feature `getrandom`, generates a 16-byte salt), `hash_password_with_rng<R: TryCryptoRng>(&mut rng, pw)`
(feature `rand_core` — **not** on by default; the probe hit "no method `hash_password_with_rng`"
without it), `hash_password_with_salt(pw, salt)`, `PasswordVerifier::verify_password(&self, pw, &PasswordHash)`
(uses the params **from the PHC string**, constant-time output compare), `generate_salt()`.
**The `PasswordHash::new(&str)` type is `argon2::password_hash::phc::PasswordHash`** (module
`phc`), not the 0.5 path.

Verified snippet (probe):
```rust
use argon2::{Argon2, Algorithm, Version, Params};
use argon2::password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash};
let params = Params::new(64 * 1024 /*KiB = 64 MiB*/, 3, 1, Some(32))?;
let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
// (a) raw KDF — for OPAQUE-independent key derivation (salt must be unique, >= 8 bytes)
let mut key = [0u8; 32]; a2.hash_password_into(password, &salt16, &mut key)?;
// (b) PHC string for stored verifier ("$argon2id$v=19$m=65536,t=3,p=1$<salt>$<hash>")
let phc = a2.hash_password(password)?.to_string();
let parsed = PasswordHash::new(&phc)?;
Argon2::default().verify_password(password, &parsed)?;      // Err(PasswordInvalid) on mismatch
```
Probe output: `$argon2id$v=19$m=65536,t=3,p=1$...`; defaults `m=19456 t=2 p=1 out=32`.
Recommendation for Tornect's unattended-access password: **use OPAQUE (§8) as the
verifier**, so the host never stores anything password-equivalent; use argon2 0.6 directly
only where a PHC verifier is genuinely wanted (e.g., local "settings lock"). Parameter choice
`m=64 MiB, t=3, p=1` costs ~0.1–0.3 s on a laptop; the OPAQUE KSF should use the *same*
argon2 parameters (via argon2 0.5's identical `Params::new`, see §8.3).

---

## 8. opaque-ke 4.0.1 (password-authenticated key exchange for unattended access)

### 8.1 Dependencies, features, conflicts
`opaque-ke-4.0.1/Cargo.toml`: `argon2 = "0.5"` (opt), `curve25519-dalek = "4"` (opt),
`ed25519-dalek = "2"` (opt), `digest = "0.10"`, `hkdf/hmac = "0.12"`, `rand = "0.8"`
(default-features=false), `voprf = "0.5"` (`danger`), `generic-array = "=0.14.7"`, `serde` (opt),
`zeroize 1.8`. Features: `default = ["ristretto255", "serde"]`, `argon2 = ["dep:argon2"]`,
`ristretto255`, `curve25519` (Curve25519 as KE group only), `ed25519`, `ecdsa`, `std`
(= `dep:getrandom` **only on wasm32**, `[target.'cfg(target_arch = "wasm32")'.dependencies.getrandom]`).
MSRV 1.85, edition 2024. CHANGELOG 4.0.0: synced with **RFC 9807**, SIGMA-I added, `KeGroup`
removed from `CipherSuite` (now inside `KeyExchange`), dummy record always created
(timing), serialized `ServerSetup` format changed vs v3.

**argon2 0.5 vs 0.6:** opaque-ke's `impl Ksf for argon2::Argon2<'_>` (`src/ksf.rs` 38–47) is
for **argon2 0.5**. Having argon2 0.6 in the same tree is fine (probe: both 0.5.3 and 0.6.0
present, resolves, links, runs). Name the 0.5 type via the re-export `opaque_ke::argon2`
(`src/lib.rs`: `#[cfg(feature = "argon2")] pub use argon2;`) — do **not** write
`type Ksf = argon2::Argon2` while `argon2 0.6` is the crate in scope; it will not implement
`Ksf`. The `Ksf` impl hashes with a **fixed all-zero 16-byte salt** (`ksf.rs` 43: 
`self.hash_password_into(&input, &[0; argon2::RECOMMENDED_SALT_LEN], &mut output)`) — that's
by design (OPAQUE's input is already the OPRF-randomized password). `ksf: None` ⇒
`CS::Ksf::default()` (`src/opaque.rs` ~1009–1017) = argon2 0.5 `Argon2::default()` =
Argon2id v19, m=19456 KiB, t=2, p=1 (`~/.cargo/registry/src/*/argon2-0.5.3/src/params.rs` 42–61,
`src/lib.rs` 176–180).

**rand:** every `start`/`finish`/`new` takes `R: rand::CryptoRng + rand::RngCore` from
**rand 0.8** (`src/opaque.rs` 19, 163, 308, 328, 507, 531, 771). Use the adapter from §3.4
or rand 0.8's `OsRng`. **Gotcha:** `use opaque_ke::*;` imports the re-export `rand` (0.8) and
`generic_array`, shadowing your `rand 0.10` — the probe hit "expected function, found module
`rand::rng`"; write `::rand::rng()` or don't glob-import.

### 8.2 CipherSuite (`src/ciphersuite.rs` 17–50)
```rust
pub trait CipherSuite where /* generic-array bounds */ {
    type OprfCs: voprf::CipherSuite;      // Ristretto255 impls voprf::CipherSuite (group + Sha512)
    type KeyExchange: KeyExchange;        // TripleDh<G, H> or SigmaI<SIG, KE, KEH>
    type Ksf: Ksf;                        // ksf::Identity or argon2 0.5 Argon2<'_>
}
// Ksf trait (src/ksf.rs 7–12): fn hash<L: ArrayLength<u8>>(&self, input: GenericArray<u8, L>) -> Result<GenericArray<u8, L>, InternalError>; requires Default
```
Verified Tornect suite (probe):
```rust
struct TornectOpaque;
impl opaque_ke::CipherSuite for TornectOpaque {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2_010::Sha512>; // sha2 **0.10** (digest 0.10)
    type Ksf = opaque_ke::argon2::Argon2<'static>;                                       // argon2 **0.5**
}
```
The hash **must** be a digest-0.10 type: `sha2 = "0.11"`'s `Sha512` does not satisfy
`opaque_ke::hash::Hash` (built on `digest 0.10::core_api::CoreProxy`). Alias the old crate
(`sha2_010 = { package = "sha2", version = "0.10" }`).

### 8.3 Full registration flow (verified; `src/lib.rs` doc 60–330, `src/opaque.rs`)
```rust
use opaque_ke::*;  // (mind the `rand` shadowing)
let server_setup = ServerSetup::<TornectOpaque>::new(&mut srng);   // persist! serialize() = 128 bytes, deserialize(&[u8])
let ksf = opaque_ke::argon2::Argon2::new(opaque_ke::argon2::Algorithm::Argon2id, opaque_ke::argon2::Version::V0x13,
                                         opaque_ke::argon2::Params::new(64 * 1024, 3, 1, None)?);
let ids = Identifiers { client: Some(b"device:<client_pk_hex>"), server: Some(b"host:<onion>") };  // Identifiers<'a>{client: Option<&[u8]>, server: Option<&[u8]>} (opaque.rs 827)
let cred_id: &[u8] = b"device:<client_pk_hex>";   // server-side DB key; not sent to client by the protocol

// client
let reg_start = ClientRegistration::<TornectOpaque>::start(&mut crng, password)?;     // .message: RegistrationRequest (32 B), .state: ClientRegistration (persist until finish)
// server
let srv_reg = ServerRegistration::<TornectOpaque>::start(&server_setup, RegistrationRequest::deserialize(&bytes)?, cred_id)?;  // .message: RegistrationResponse (64 B)
// client
let reg_fin = reg_start.state.finish(&mut crng, password, RegistrationResponse::deserialize(&bytes)?,
        ClientRegistrationFinishParameters::new(ids, Some(&ksf)))?;      // or ClientRegistrationFinishParameters { identifiers, ksf, } / ::default()
//   reg_fin.message: RegistrationUpload (192 B)  reg_fin.export_key: Output<Sha512> (64 B)  reg_fin.server_s_pk: PublicKey (serialize() = 32 B)
// server
let password_file = ServerRegistration::<TornectOpaque>::finish(RegistrationUpload::deserialize(&bytes)?);   // serialize() = 192 B -> store under cred_id
```

### 8.4 Full login flow with context (verified)
```rust
// context = what we want the session key bound to: transcript hash || session_token (any bytes; SerializedContext::from(Option<&[u8]>) in opaque.rs 801)
let mut context = Vec::new(); context.extend_from_slice(&transcript_hash); context.extend_from_slice(&session_token);

// client
let ls = ClientLogin::<TornectOpaque>::start(&mut crng, password)?;    // .message: CredentialRequest / KE1 (96 B); .state: ClientLogin (serialize() = 192 B)
// server
let pf = ServerRegistration::<TornectOpaque>::deserialize(&stored)?;    // or None -> dummy response (same size, RFC 9807 §"Dummy Server Login")
let ss = ServerLogin::start(&mut srng, &server_setup, Some(pf), CredentialRequest::deserialize(&ke1)?, cred_id,
        ServerLoginParameters { context: Some(&context), identifiers: ids })?;   // .message: CredentialResponse / KE2 (320 B); .state: ServerLogin (serialize() = 128 B)
// client
let lf = ls.state.finish(&mut crng, password, CredentialResponse::deserialize(&ke2)?,
        ClientLoginFinishParameters::new(Some(&context), ids, Some(&ksf)))?;    // fields: { context, identifiers, ksf } (opaque.rs 903–927)
//   lf.message: CredentialFinalization / KE3 (64 B)  lf.session_key: Output<Sha512> (64 B)  lf.export_key (64 B)  lf.server_s_pk
//   Err(ProtocolError::InvalidLoginError) on wrong password / wrong context / wrong identifiers
// server
let sf = ss.state.finish(CredentialFinalization::deserialize(&ke3)?, ServerLoginParameters { context: Some(&context), identifiers: ids })?;
assert_eq!(sf.session_key, lf.session_key);
```
Probe asserted: wrong `context` on the client ⇒ `finish` errors; wrong password ⇒ errors;
`None` password file ⇒ KE2 byte-length identical (320 B) to the real one;
`lf.server_s_pk == reg_fin.server_s_pk` (check this on the client to detect a swapped host,
lib.rs doc "Checking Server Consistency"); `export_key` identical across registration/login.

**Sizes (Ristretto255 + TripleDh/Sha512, measured in probe via `.serialize()`):**
`ServerSetup` 128 · `RegistrationRequest` 32 · `RegistrationResponse` 64 · `RegistrationUpload` 192 ·
`ServerRegistration` (password file) 192 · `CredentialRequest` (KE1) 96 · `CredentialResponse`
(KE2) 320 · `CredentialFinalization` (KE3) 64 · `ClientLogin` state 192 · `ServerLogin` state 128 ·
`session_key` 64 · `export_key` 64 · `server_s_pk` 32. All messages have `serialize() ->
GenericArray<u8, ..Len>` and `deserialize(&[u8]) -> Result<_, ProtocolError>`
(`src/messages.rs`); the `..Len` typenums are exported (`RegistrationRequestLen`, etc.).
**For the CBOR envelope carry the raw `serialize()` bytes as a CBOR byte string** — the
`serde` derive of `CredentialRequest` produced 245 B vs 96 B raw (serde encodes the
inner structs field-by-field).

`session_key` semantics (lib.rs doc "Session Key"): pseudorandom, length = OPRF hash output
(64 B for Sha512), fresh per login, known only to both sides ⇒ use it (via HKDF) to key the
unattended-session authorization token / bind to the QUIC exporter. `export_key`: derived
from the password only (never seen by the server), same across logins ⇒ can encrypt
client-side secrets; Tornect probably does not need it.

Persisting: `ServerSetup::serialize()/deserialize()` (opaque.rs 208/224) — **secret** (contains
the OPRF seed and server static key); keep it with the host identity key. The password file
(`ServerRegistration`) is "about as sensitive as a hash of the password" (lib.rs doc) — store
with 0600. Registration must run over an authenticated channel (our Tor stream + pairing).
Remote-key / remote-OPRF-seed builder APIs exist (`ServerLogin::builder`, `start_with_key_material`)
if the server key ever goes into a keychain/HSM.

---

## 9. Onion v3 address encoding / decoding

Spec (tor rend-spec-v3 §6 "[ONIONADDRESS]", as implemented in `tor-hscrypto-0.45.0/src/pk.rs`
118–140, 166–255):
```
onion_address = base32( PUBKEY || CHECKSUM || VERSION ) + ".onion"
CHECKSUM      = SHA3-256( ".onion checksum" || PUBKEY || VERSION )[0..2]
VERSION       = 0x03
PUBKEY        = 32-byte ed25519 public key (KP_hs_id)  → 35 bytes → 56 base32 chars (lowercase, no padding) → 62 chars total
```
**Arti already implements it — reuse `tor_hscrypto::pk::HsId`:**
- `pub struct HsId([u8; 32])` via `define_bytes!` ⇒ `From<[u8;32]>`, `Into<[u8;32]>`, `AsRef<[u8;32]>`, `Copy/Eq/Hash` (`pk.rs` 31–47).
- `impl FromStr for HsId` (`pk.rs` 166–208): strips `.onion` case-insensitively, rejects
  subdomains, uppercases and decodes with `data_encoding::BASE32_NOPAD`, checks
  `version == 0x03` **before** the checksum, recomputes the SHA3-256 checksum. Error enum
  `HsIdParseError { NotOnionDomain, InvalidBase32, InvalidData, UnsupportedVersion(u8), WrongChecksum, HsIdContainsSubdomain }` (210–239).
- **No plain `Display`**: `impl safelog::DisplayRedacted for HsId` (`pk.rs` 123–152) —
  `hsid.display_unredacted().to_string()` gives the full address; `Display` on the redacted
  wrapper prints only the tail (`…lxid.onion`) for logs. Add `safelog = "0.9"` and
  `use safelog::DisplayRedacted;`.
- `HsIdKey` (expanded `ed25519::PublicKey`) ⇄ `HsId` via `id()`/`TryFrom` (`pk.rs` 88–103).
- `RunningOnionService::onion_address() -> Option<HsId>` (see `docs/research/arti.md` §8).

Stand-alone implementation (for the client crate if you don't want `tor-hscrypto` there),
verified in the probe to be **byte-identical to `HsId::display_unredacted()`**, to round-trip
through `HsId::from_str`, and to encode/decode the public DuckDuckGo address
`duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion`:
```rust
fn onion_v3_encode(pk: &[u8; 32]) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new(); h.update(b".onion checksum"); h.update(pk); h.update([0x03u8]);
    let checksum = h.finalize();
    let mut bin = Vec::with_capacity(35); bin.extend_from_slice(pk); bin.extend_from_slice(&checksum[..2]); bin.push(0x03);
    let mut s = data_encoding::BASE32_NOPAD.encode(&bin); s.make_ascii_lowercase(); s.push_str(".onion"); s
}
fn onion_v3_decode(addr: &str) -> Result<[u8; 32], String> {
    use sha3::{Digest, Sha3_256};
    let body = addr.strip_suffix(".onion").ok_or("no .onion suffix")?;
    if body.len() != 56 { return Err(format!("bad length {}", body.len())); }
    let bin = data_encoding::BASE32_NOPAD.decode(body.to_ascii_uppercase().as_bytes()).map_err(|e| e.to_string())?;
    if bin.len() != 35 || bin[34] != 0x03 { return Err("bad version/length".into()); }
    let pk: [u8; 32] = bin[..32].try_into().unwrap();
    let mut h = Sha3_256::new(); h.update(b".onion checksum"); h.update(pk); h.update([0x03u8]);
    if !bool::from(subtle::ConstantTimeEq::ct_eq(&h.finalize()[..2], &bin[32..34])) { return Err("checksum".into()); }
    Ok(pk)
}
```
data-encoding 2.11.1 (`data-encoding-2.11.1/src/lib.rs`): `BASE32_NOPAD` (2264) is RFC 4648
**uppercase**, decode rejects lowercase — hence the uppercase step (Arti does the same,
`pk.rs` 176–187). `BASE32_NOPAD_NOCASE` (2304) accepts either case on decode if you prefer
(`spec.translate.from = "a..z"` → `"A..Z"`). `Encoding::encode(&[u8]) -> String` (1504),
`decode(&[u8]) -> Result<Vec<u8>, DecodeError>` (1640). Note the decoded key should
additionally pass `VerifyingKey::from_bytes` (canonical point) before use as an ed25519 key.

---

## 10. Constant-time comparison, zeroization

- **`subtle 2.6.1`** (`subtle-2.6.1/Cargo.toml`: features `std`, `i128` default, `const-generics`,
  `core_hint_black_box`): `ConstantTimeEq::ct_eq(&a, &b) -> Choice`, `bool::from(choice)`;
  impls for `[u8]`, `[u8; N]` (const-generics; curve25519-dalek 5 requires that feature so it's
  on in the tree). Already a dependency of dalek, opaque-ke, and Arti ⇒ **use this**.
- `constant_time_eq 0.5.0`: `constant_time_eq(&[u8], &[u8]) -> bool`, `_n<const N>`, `_16/_32/_64`
  (`src/lib.rs` 86–153) — but **MSRV 1.95** (crates.io `rust_version`), and blake3 pins
  `0.4.2`, so you'd get two copies. Not needed; subtle covers it. `hmac::Mac::verify_slice`
  and `digest::CtOutput` already compare MACs in constant time; `blake3::Hash` `PartialEq` too.
- **`zeroize 1.9.0`** (`zeroize-1.9.0/Cargo.toml`, `src/lib.rs` 214–604): features
  `default = ["alloc"]`, **`derive`** (= `zeroize_derive 1.5`, gives `#[derive(Zeroize, ZeroizeOnDrop)]`),
  `std`, `serde`. `Zeroizing<Z>` wrapper (now `?Sized` + `repr(transparent)`, CHANGELOG 1.9.0),
  `zeroize_stack`, `optimization_barrier`. dalek 3 `SigningKey` is `ZeroizeOnDrop` with the
  default `zeroize` feature; x25519 secrets zeroize on drop (no `Zeroize` impl, by design).
  Probe used `#[derive(Zeroize, ZeroizeOnDrop)] struct Secret([u8; 32]);` and `Zeroizing::new(vec)`.

---

## 11. Build requirements (this VM vs CI)

| crate | native build step | tools needed | on this VM |
|---|---|---|---|
| curve25519-dalek 5 | `build.rs` picks `curve25519_dalek_bits` / `curve25519_dalek_backend` (`simd` auto on x86_64) using `rustc_version`; `curve25519-dalek-derive` proc-macro; optional `fiat` backend via `RUSTFLAGS='--cfg curve25519_dalek_backend="fiat"'` | none | **OK** |
| sha2 0.11 / sha3 / hmac / hkdf / argon2 0.6 / zeroize / subtle / rand / getrandom | pure Rust; `cpufeatures` runtime detection | none | **OK** |
| getrandom 0.4.3 | `libc` on Linux/macOS; Windows `ProcessPrng` | none | OK |
| blake3 1.8.7 | `build.rs` compiles `c/blake3_{sse2,sse41,avx2,avx512}_x86-64_unix.S` with the `cc` crate (`build.rs` 216–269); MSVC uses `.asm` via MASM (`ml64`, ships with VS Build Tools) — **no nasm**; `pure` feature disables all C/asm; `prefer_intrinsics` uses C intrinsics | a C compiler (gcc here; MSVC/clang on Win/mac) | **OK** (built) |
| opaque-ke 4.0.1 | pure Rust (`curve25519-dalek 4` has its own build.rs, same story) | none | **OK** |
| tor-hscrypto 0.45.0 | pure Rust in the default (non-openssl) config | none | **OK** (built here and in `/tmp/probe-arti`) |

No cmake, nasm, bindgen/libclang, pkg-config or system dev headers are involved anywhere in
this topic. Full probe (`cargo build`, debug, `CARGO_BUILD_JOBS=2`) compiled from a warm
registry in a few minutes; incremental rebuild 2.8 s. Windows/macOS: no extra tooling beyond
the platform C toolchain (only blake3 needs it; drop blake3 or use `pure` to avoid even that).

---

## 12. Gotchas

1. **`SigningKey::generate` needs feature `rand_core`**, and `to_pkcs8_der`/`to_public_key_der`
   need **`alloc` + `pkcs8`** (probe failure until added). `pem` implies both.
2. **rand_core 0.10 renamed the traits**: `RngCore`→`Rng`, `TryRngCore`→`TryRng`; `OsRng` is
   gone (`getrandom::SysRng` + `UnwrapErr`). Code copied from 2024/2025 blog posts won't compile.
3. **Three `rand_core`s in the tree** (0.6 for opaque-ke/voprf/dalek-2, 0.10 for us and Arti).
   A `ThreadRng` from rand 0.10 is not a rand-0.8 `RngCore`; use the §3.4 adapter. Arti's
   `RngCompat` is `pub` only under `tor-llcrypto`'s `rng-compat` feature (`util/rng.rs` 11) —
   easier to copy the 20 lines.
4. **`use opaque_ke::*` shadows `rand`** (re-export of rand 0.8) and brings `generic_array`.
5. **opaque-ke's `Ksf` is for argon2 0.5** (`opaque_ke::argon2`); the KE hash must be **sha2
   0.10** (`sha2_010` alias). Neither conflicts with the 0.6/0.11 versions elsewhere.
6. opaque-ke `ServerLogin::start(.., None, ..)` (dummy record) must be used for unknown
   credential ids to avoid user enumeration; it was verified to produce a same-size KE2.
7. `Identifiers`/`context` must be **identical** in `ClientRegistrationFinishParameters`
   (identifiers only), `ServerLoginParameters` (start **and** finish) and
   `ClientLoginFinishParameters`, or `finish` fails with `InvalidLoginError`.
8. **digest 0.11.0 / 0.11.1 are yanked**; `cargo update` if a lockfile ever pins them.
9. `hkdf 0.13` renamed the concrete struct to `GenericHkdf`; the `Hkdf<H>` alias still exists,
   `expand` returns `Err(InvalidLength)` when `okm.len() > 255 * HashLen`.
10. sha3 0.12 removed `Shake*` (moved to the `shake` crate); Arti still uses sha3 0.10 — two
    copies, harmless.
11. `x25519-dalek 3` removed `Zeroize` impls on secrets (drop-only zeroization) — don't
    `derive(Zeroize)` on structs that contain them; wrap in `Option` or rely on drop.
12. `HsId` has **no `Display`** (`safelog::DisplayRedacted` instead); `HsId::from_str` accepts
    upper/lower/mixed case and rejects subdomains — apply `trim()` on user input yourself.
13. `constant_time_eq 0.5` needs Rust 1.95; blake3 pins 0.4.2. Prefer `subtle`.
14. argon2 0.6's `password-hash` feature is the renamed `simple`; `PasswordHash` now lives at
    `password_hash::phc::PasswordHash`; `hash_password_with_rng` needs feature `rand_core`.
15. `rand` crate on crates.io shows `newest_version = 0.8.8` (a backport release); pin `=0.10.2`.
16. ed25519-dalek 3 `serde` output for keys in CBOR is a byte string (`serdect`), not an
    array — 34 bytes for a 32-byte key. Fine for our envelope; just don't expect a hex string
    in binary formats.

---

## 13. Open questions

1. **opaque-ke on the new stack**: `voprf 0.6.0-pre.1` moved to rand_core 0.9 (not 0.10) and
   `opaque-ke 4.1.0-pre.2` still uses argon2 0.5 / rand 0.8. A future opaque-ke 5 will likely
   flip to digest 0.11 / rand_core 0.10 and argon2 0.6 — track
   https://github.com/facebook/opaque-ke/releases; until then the aliases in §8 stay.
2. **Which key signs `SESSION_ACCEPT` on the host** (plan §B.3): the onion identity key
   (expanded form, `ExpandedKeypair::sign` via Arti's keymgr) or a separate host *device* key
   (dalek 3 `SigningKey`)? Either is verifiable with dalek 3 `VerifyingKey`; the onion key
   binds the signature to the address the user typed (stronger), the device key is simpler
   to manage. Recommend: onion key for `SESSION_ACCEPT`/`PAIR_ACCEPT`, and pin a per-host
   device key too for QUIC cert SPKI.
3. Argon2 parameters for the OPAQUE KSF: default (19 MiB, t=2) vs 64 MiB, t=3. Client-side
   cost only (the KSF runs on the client in OPAQUE). Decide with UX (mobile clients later).
4. Whether to declare `context` as `SHA256(transcript) || session_token` (96 B, used in probe)
   or a single HKDF-derived 32-byte binder — pure protocol-design choice; both work.
5. `blake3`: not needed for the handshake at all; keep as an optional dependency for file
   transfer / restore-token hashing, or drop to avoid the C toolchain requirement on
   contributor machines (it built fine here).

---

## 14. Probe evidence (this VM, 2026-08-28)

- Crate: `/tmp/probe-crypto` (`Cargo.toml`, `src/main.rs`; `Cargo.lock` has the resolved set).
  Command: `CARGO_BUILD_JOBS=2 cargo build` → `Finished dev profile`; `./target/debug/probe-crypto`:
  ```
  rand 0.10: rng()/random()/UnwrapErr(SysRng)/getrandom::fill/ChaCha20Rng OK
  ed25519-dalek 3: pkcs8 private DER = 83 bytes, SPKI DER = 44 bytes
  ed25519-dalek 3: CBOR(VerifyingKey) = 34 bytes, CBOR(Signature) = 66 bytes
  x25519-dalek 3: DH OK
  sha2/hmac/hkdf 0.11/0.13: OK, SAS = 206016
  blake3 1.8: OK
  subtle/constant_time_eq/zeroize: OK
  argon2 0.6: hash_password_into OK; PHC = $argon2id$v=19$m=65536,t=3,p=1$AqAujmtep
  argon2 0.6 defaults: m=19456 t=2 p=1 out=32
  opaque-ke 4.0.1 sizes: ServerSetup=128 RegistrationRequest=32 RegistrationResponse=64 RegistrationUpload=192 ServerRegistration(password file)=192 export_key=64 server_s_pk=32
  opaque-ke 4.0.1 sizes: CredentialRequest(KE1)=96 CredentialResponse(KE2)=320 CredentialFinalization(KE3)=64 ClientLogin state=192 ServerLogin state=128 session_key=64
  opaque-ke 4.0.1: CBOR(CredentialRequest) via serde = 245 bytes (vs 96 raw)
  opaque-ke 4.0.1: full registration+login with context+identifiers+argon2id OK
  onion v3: ours == tor-hscrypto HsId (62 chars): uekzuvyadi4rdvtpcedx4g46ww64ywo2mqbqarhd7o547byrncaalxid.onion
  ALL OK
  ```
- `cargo tree -i curve25519-dalek@4.1.3` → only via `ed25519-dalek 2.2.0 ← tor-llcrypto` and
  `opaque-ke`/`voprf`/`x25519-dalek 2.0.1`; `cargo tree -i argon2@0.5.3` → only `opaque-ke 4.0.1`;
  `cargo tree -i getrandom@0.2.17` → only `rand_core 0.6.4`.
- Two compile errors encountered and fixed (documented as gotchas 1, 4, 14): missing `alloc`
  feature on ed25519-dalek; `rand` shadowed by `opaque_ke::*`; `hash_password_with_rng`
  behind argon2's `rand_core` feature.
- Extracted sources consulted: `/tmp/crates-src/{ed25519-dalek-3.0.0, x25519-dalek-3.0.0,
  curve25519-dalek-5.0.0, ed25519-3.0.0, signature-3.0.0, sha2-0.11.0, sha3-0.12.0, sha3-0.11.0,
  hmac-0.13.0, hkdf-0.13.0, digest-0.11.3, argon2-0.6.0, password-hash-0.6.1, opaque-ke-4.0.1,
  opaque-ke-4.1.0-pre.2, voprf-0.5.0, voprf-0.6.0-pre.1, rand-0.10.2, rand_core-0.10.1,
  rand_chacha-0.10.0, getrandom-0.4.3, zeroize-1.9.0, subtle-2.6.1, blake3-1.8.7,
  data-encoding-2.11.1, constant_time_eq-0.5.0, tor-hscrypto-0.45.0, tor-llcrypto-0.45.0}`
  and `~/.cargo/registry/src/index.crates.io-*/{argon2-0.5.3, hybrid-array-0.4.14, tor-llcrypto-0.45.0}`.
