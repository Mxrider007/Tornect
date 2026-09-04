# M1 golden vectors — `tornect-core::unattended` (U6)

Pinned by `unattended::codec::tests::u6_hkdf_golden_vectors_k_unatt_k_log` and cross-checked
on 2026-08-29 against an independent HKDF/HMAC implementation (Python `hmac`/`hashlib`,
RFC 5869 extract-then-expand). A change in salt, info, order or the file layout fails the test.

## Key derivation (`docs/PLAN.md` §B.8.9, §B.8.13)

```
K_master = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f   (32 bytes, 00..1f)
K_unatt  = HKDF-SHA256(ikm = K_master, salt = "tornect/v1/keystore", info = "unattended-store", 32)
         = 6dd4bffa8cb4208c2ad98419052248708e1f8c11a173c74ea856c11177d00c96
K_log    = HKDF-SHA256(ikm = K_master, salt = "tornect/v1/keystore", info = "log", 32)
         = 443b6fc2e74166d8657e8a4b3e96d2b1ad1d4714b8e850e66857e4f629a7d06b
```

## Log tag

```
line_without_tag = {"ts":"2026-08-29T00:00:00Z","event":"grant_created","prev":null}
tag = HMAC-SHA256(K_log, line_without_tag)
    = ac00659ea167af7414b63d2c1635155915f16c2b82414cf95c6aed7a0d5812e0
written line     = {"ts":"2026-08-29T00:00:00Z","event":"grant_created","prev":null,"tag":"ac00…12e0"}
```

`prev` = SHA-256 of the previous line (without its newline); `tag = null` while no
`K_master` exists.

## Store file

`UnattendedStore::bootstrap(server_setup = 0x11 × 16, machine_id_hash = 0x22 × 32, now = 1756425600)`
(schema 1, disabled, defaults 20 / keep-awake on / notify on, no grants, `pending_anchor = 1`):

```
CBOR(UnattendedStore) =
ad000101f4035011111111111111111111111111111111051406f507f408f509800a800b5820
0000000000000000000000000000000000000000000000000000000000000000
0c1a68b0ed800d010e5820
2222222222222222222222222222222222222222222222222222222222222222

header  = "TNUA" || 0x01 || u64be(1) || nonce (0x33 × 24)
file    = header || XChaCha20-Poly1305(K_unatt, nonce, CBOR, aad = header) =
544e5541 01 0000000000000001 333333333333333333333333333333333333333333333333
2e3699eb190527c237f9145eee2d939d00f5624076666efb0c3f64ec3028e20ae1e94202e1f3ac14
c96a41d35bf2833e92a3f9d917f4bac9d0280597e3b156b1032b8d22f3ceabf9e79cbe7199d8bfb8
5e7123cbdb134a04e25dbba1b3f8dc870baa6e48cda6a14680a55bde55547110ab2fcae487c044dd
6bbbf7e74b350bd1d7
```

CBOR map keys of `UnattendedStore`: 0 schema_version · 1 enabled · 2 paused_until ·
3 server_setup (bstr) · 4 stop_token (bstr?) · 5 default_hard_lock_after · 6 keep_awake ·
7 prevent_idle_lock · 8 notify · 9 grants · 10 tombstones (`[[device(bstr32), unix]]`) ·
11 log_chain_head (bstr32) · 12 last_seen_unix · 13 pending_anchor · 14 machine_id_hash (bstr32?).
`UnattendedGrant` keys 0–23 and `FailState` keys 0–8 are listed on the structs in
`crates/tornect-core/src/unattended/grant.rs`.

## Machine id hash

```
SHA-256("tornect/v1/machine-id\0" || "abc") = 9b5bad77105f8a9a909913d19e1e1ff016e75117b3feb96f26b5cd11b28eeed0
```
