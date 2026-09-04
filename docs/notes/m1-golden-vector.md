# M1 golden vectors — envelope / transcript / signatures / SAS (docs/PLAN.md §B.8.4.3)

Decision M1-10. Pinned by the unit tests `fsm::golden::golden_vector_attended_exchange`
(vector 1) and `fsm::golden::golden_vector_pairing_exchange` (vector 2) in
`crates/tornect-signal/src/fsm/golden.rs`; the fixed inputs live in
`tornect_signal::fsm::vectors`, which the F1 fuzz harness and the committed fuzz seeds
(`fuzz/seeds/envelope/`, checked by `fsm::golden::fuzz_seeds_match_the_golden_vectors_and_reach_a_session`)
share. Any change to the envelope encoding, a body key number, the transcript chain or the
signature input changes these bytes, and both the tests and this note must then be
regenerated together with a decision-log entry saying why.

Regenerated 2026-08-29 after decision M1-31 (`SESSION_ACCEPT.quic_spki` = SPKI of the host
*device* key pinned at pairing, no longer the onion key): `frame_4` / `digest_4` / `sig_4` /
`th_4` of vector 1 changed; `frame_1..3` did not.

## Inputs (all fixed, `tornect_signal::fsm::vectors`)

| Input | Value |
|---|---|
| Host onion identity seed | `11` × 32 |
| Host onion public key (`host_onion_pk`, `th_0` input, `HELLO_ACK` / `SESSION_ACCEPT` signer) | `d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737` |
| Client device identity seed | `22` × 32 |
| Client device public key (`HELLO.device_pk`, `HELLO` / `SESSION_REQUEST` signer) | `a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0` |
| Host *device* identity seed | `B0` × 32 |
| Host device public key (`PAIR_ACCEPT.host_device_pk`; `SESSION_ACCEPT.quic_spki` = its RFC 8410 SPKI) | `705fbac01f5519899f437bc42e40255ae9ab54bff00de3433af7d687d9e71ad5` |
| `HELLO.client_nonce` | `33` × 32 |
| `HELLO_ACK.host_nonce` | `44` × 32 |
| Attended `session_token` (host RNG, `ConsentProof::HumanClick`) | `55` × 32 |
| `HELLO` | `v_max = 1`, `name = "golden-client"`, `feats = ["ua1"]`, no `stop_token`, `pairing_state = 1` (vector 1) / `0` (vector 2) |
| `HELLO_ACK` | `v = 1`, `feats = ["ua1"]` |
| `PAIR_REQUEST` (vector 2) | `client_auth_pk` absent |
| `PAIR_ACCEPT` (vector 2) | `host_device_pk` above, `host_name = "golden-host"` |
| `SESSION_REQUEST` | `caps = { codecs: ["h264"], max_res: 1920×1080, hdr: false, monitors: 1 }`, attended (`unattended` absent) |
| Host caps | `codecs: ["h264", "av1"], max_res: 2560×1440, hdr: true, monitors: 2` ⇒ negotiated `["h264"], 1920×1080, hdr false, monitors 1` |
| Consent | pairing popup Allow (declared name kept as label), session popup `AllowOnce` ⇒ `session_type 0`, `mode 0`, `transport_policy 0` (Any), `block_window_s 0`, `ask_before_start false` |
| `quic_spki` | RFC 8410 SPKI DER of the host *device* pk (`302a300506032b6570032100` ‖ pk) — decision M1-31 |
| Device state | vector 1: already paired on the host (no `PAIR_REQUEST` / `PAIR_ACCEPT`); vector 2: unpaired on both sides |

Envelope `v = 1` on every frame; `msg_id` counts from 1 in each direction.

## Chain

```
th_0 = SHA-256("tornect/v1/transcript\0" || host_onion_pk)
th_i = SHA-256(th_{i-1} || frame_i)                       // frame_i = u32-BE length || CBOR envelope
digest_i = SHA-256(u8 v || u64-BE msg_id || u8 kind || body)
sig_i = Ed25519(sk, "tornect/v1/sig/" || KIND_NAME || "\0" || th_{i-1} || digest_i)
SAS = u32::from_be_bytes(HKDF-SHA256(ikm = th_after(PAIR_REQUEST), salt = "tornect/v1/sas", info = "sas-v1")[0..4]) % 1_000_000
```

## Vector 1 — paired device (`HELLO → HELLO_ACK → SESSION_REQUEST → SESSION_ACCEPT`)

| # | Value | Hex |
|---|---|---|
| 0 | `th_0` | `8cc466fe5dfebdc9b12920ad7bcd2de8ee6155a4ac9737101cee047b1ab19a0f` |
| 1 | `frame_1_hello` (`HELLO`, client, msg_id 1) | `000000a8850101015860a600010158203333333333333333333333333333333333333333333333333333333333333333025820a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0036d676f6c64656e2d636c69656e74048163756131060158408c042e6af9dec69da1574ad709fa6f80355c796bfd54454ab0dada974ac968e4d36a8e98fc339d8ee4b5525bab3411c70b696fe91c83add63c30163952308407` |
| 1 | `digest_1` | `42cdaa1c8f0d516921d909220ae83fd0ce893aa130dd3836c94e65aceda82290` |
| 1 | `sig_1` (client device key, over `th_0`) | `8c042e6af9dec69da1574ad709fa6f80355c796bfd54454ab0dada974ac968e4d36a8e98fc339d8ee4b5525bab3411c70b696fe91c83add63c30163952308407` |
| 1 | `th_1` | `12e5f2ef93eddf1fa66d21bfd57a7a5d7ab440393afa15c985f0a96638c98443` |
| 2 | `frame_2_hello_ack` (`HELLO_ACK`, host, msg_id 1) | `0000007485010102582ca30001015820444444444444444444444444444444444444444444444444444444444444444402816375613158409a2a86ae7b26c080d2e1ed51c5b29bb29947423548503fba15cb25e261fa792da5df9b8d10d19993a3d5c6f2a7055bb836101a40f7acca5c67bf590298143108` |
| 2 | `digest_2` | `87fbc62c64df8998566f919714fe3c8c2132737d56166b9c95dcf4e5ce98acd0` |
| 2 | `sig_2` (host onion key, over `th_1`) | `9a2a86ae7b26c080d2e1ed51c5b29bb29947423548503fba15cb25e261fa792da5df9b8d10d19993a3d5c6f2a7055bb836101a40f7acca5c67bf590298143108` |
| 2 | `th_2` | `da523df7c6b7a4dda138c3ac970db657faaa5c721c46acca6cd8f89f095a0a1a` |
| 3 | `frame_3_session_request` (`SESSION_REQUEST`, client, msg_id 2) | `0000005d8501020656a100a400816468323634018219078019043802f403015840d364bf0d9390181088f3118379c2f10f45a4eae1d718792fa32d58decbb24cd4d624c5dea3283b343d06c2d55718c9af5dc4968ab20d41afac42398f59ae1f01` |
| 3 | `digest_3` | `832201e56df8eef50c7d96bf2b5574d1cb32f3aa932f90d4b82dd58379fac3cb` |
| 3 | `sig_3` (client device key, over `th_2`) | `d364bf0d9390181088f3118379c2f10f45a4eae1d718792fa32d58decbb24cd4d624c5dea3283b343d06c2d55718c9af5dc4968ab20d41afac42398f59ae1f01` |
| 3 | `th_3` | `061d9ee332db832e7c3cd44061ff8ccd32dc4fe32aecb9db9c9a918fe89ea4f5` |
| 4 | `frame_4_session_accept` (`SESSION_ACCEPT`, host, msg_id 2) | `000000ba850102075872a800a400816468323634018219078019043802f4030101582c302a300506032b6570032100705fbac01f5519899f437bc42e40255ae9ab54bff00de3433af7d687d9e71ad50200030004000558205555555555555555555555555555555555555555555555555555555555555555070008f45840b014e4385e8e1d29f061df4534b376fe387bfd21a4abc3a76b4431c74c2b397944f6a50c88776119257381646ea3c21e6c8972139a2d75f2a27d737ee05b710e` |
| 4 | `digest_4` | `728405e008449e172d395bfc2133f7098a88a1d61032d3e851eabfec023b98d4` |
| 4 | `sig_4` (host onion key, over `th_3`) | `b014e4385e8e1d29f061df4534b376fe387bfd21a4abc3a76b4431c74c2b397944f6a50c88776119257381646ea3c21e6c8972139a2d75f2a27d737ee05b710e` |
| 4 | `th_4` (`th_final`, identical on both sides) | `cdf97099e56630861eb9ad965457f52a55f3347146036f7065c5eb1582bcf198` |

## Vector 2 — unpaired device (`HELLO → HELLO_ACK → PAIR_REQUEST → PAIR_ACCEPT → SESSION_REQUEST → SESSION_ACCEPT`)

| # | Value | Hex |
|---|---|---|
| 0 | `th_0` | `8cc466fe5dfebdc9b12920ad7bcd2de8ee6155a4ac9737101cee047b1ab19a0f` |
| 1 | `frame_1_hello` (`HELLO`, client, msg_id 1, `pairing_state = 0`) | `000000a8850101015860a600010158203333333333333333333333333333333333333333333333333333333333333333025820a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0036d676f6c64656e2d636c69656e740481637561310600584042d7cda78c6f698bbf5a05efc6ffe70ea52bdcfcbfe0e4833f593c70c5872164bc462976c4b47316747def7db5af0a8621d2d89e16680feb0868acee49ddc204` |
| 1 | `digest_1` | `960ddd5ea25c79e093ca5f3e3c02087a3698efe8d01921ff24409b12eb292a3e` |
| 1 | `sig_1` (client device key, over `th_0`) | `42d7cda78c6f698bbf5a05efc6ffe70ea52bdcfcbfe0e4833f593c70c5872164bc462976c4b47316747def7db5af0a8621d2d89e16680feb0868acee49ddc204` |
| 1 | `th_1` | `2787876076e98f3310e83d47ee51f97fc9e87ad5a5c5a01d110bb7c765921f75` |
| 2 | `frame_2_hello_ack` (`HELLO_ACK`, host, msg_id 1) | `0000007485010102582ca3000101582044444444444444444444444444444444444444444444444444444444444444440281637561315840c088df14d82c56ce3bb87b7b86a22b6b77bb68435985fb9025d6fea3952c0ac4f948c1e790bdd66acd3d6ab57e3804d02a695b4cd235af6ee5773f9d2dc7b205` |
| 2 | `digest_2` | `87fbc62c64df8998566f919714fe3c8c2132737d56166b9c95dcf4e5ce98acd0` |
| 2 | `sig_2` (host onion key, over `th_1`) | `c088df14d82c56ce3bb87b7b86a22b6b77bb68435985fb9025d6fea3952c0ac4f948c1e790bdd66acd3d6ab57e3804d02a695b4cd235af6ee5773f9d2dc7b205` |
| 2 | `th_2` | `10003074c3f7123641e262760a4d180681c7b523c82864b7936ad9a46c112d38` |
| 3 | `frame_3_pair_request` (`PAIR_REQUEST`, client, msg_id 2, unsigned) | `000000078501020341a0f6` |
| 3 | `th_3` = `th_after(PAIR_REQUEST)`, the SAS input | `8604d6b450520a47672097a318dbb6e55d8f722c96eb0da89268a7d3be108345` |
| 3 | `sas` (rendered) | `346 695` |
| 4 | `frame_4_pair_accept` (`PAIR_ACCEPT`, host, msg_id 2, unsigned) | `00000038850102045831a2005820705fbac01f5519899f437bc42e40255ae9ab54bff00de3433af7d687d9e71ad5016b676f6c64656e2d686f7374f6` |
| 4 | `th_4` | `5d1b5be7cf280525cbf191ee38b9babe97425238c6f82d466b9b999c903ca7b2` |
| 5 | `frame_5_session_request` (`SESSION_REQUEST`, client, msg_id 3) | `0000005d8501030656a100a400816468323634018219078019043802f403015840121252a6f442839d47ca2f8464987d7e299e3c05b5a4e44f7ae700817ae9fe75a769649cae364c53761106f959d4e4a620e084d4ac82900b246507874df2a701` |
| 5 | `digest_5` | `2b916c1a2542ce973e5c714c7235fc1487e9e0c22c42acd1846da789e2ffc2ff` |
| 5 | `sig_5` (client device key, over `th_4`) | `121252a6f442839d47ca2f8464987d7e299e3c05b5a4e44f7ae700817ae9fe75a769649cae364c53761106f959d4e4a620e084d4ac82900b246507874df2a701` |
| 5 | `th_5` | `f93a2f68627c084bc74d309177b7f44b93c42ef821da4887184e2a1c16016da4` |
| 6 | `frame_6_session_accept` (`SESSION_ACCEPT`, host, msg_id 3) | `000000ba850103075872a800a400816468323634018219078019043802f4030101582c302a300506032b6570032100705fbac01f5519899f437bc42e40255ae9ab54bff00de3433af7d687d9e71ad50200030004000558205555555555555555555555555555555555555555555555555555555555555555070008f45840d8028e6a60a247a0bbd327c577d5b253cfea085c951e689ffe04f3b4e0967d0e168bafd4c68353d66eb0e80242af45f009bcb60200df0f6413f3cf784483e609` |
| 6 | `digest_6` | `e9d7bbdd0fd5bf991fff4d4a9be1d08f19b43b0c16cb2fef86ffd0b8717c2968` |
| 6 | `sig_6` (host onion key, over `th_5`) | `d8028e6a60a247a0bbd327c577d5b253cfea085c951e689ffe04f3b4e0967d0e168bafd4c68353d66eb0e80242af45f009bcb60200df0f6413f3cf784483e609` |
| 6 | `th_6` (`th_final`, identical on both sides) | `90a4f894ca33c22793b1f2bd6b92ff29fa18c153b849abf5f0873fd6474a0556` |

## Reading the frames

Vector 1 `frame_1` decodes as `[1, 1, 1, body, sig]`; its body is the map
`{0: 1, 1: h'33…', 2: h'a09a…', 3: "golden-client", 4: ["ua1"], 6: 1}` (key 5 absent ⇒
`stop_token = None`). `frame_4`'s body is
`{0: {0: ["h264"], 1: [1920, 1080], 2: false, 3: 1}, 1: h'302a…705f…', 2: 0, 3: 0, 4: 0, 5: h'55…',
7: 0, 8: false}` (keys 6, 9, 10 absent ⇒ `token_confirm`, `ends_at`, `fail_summary` = `None`).
Vector 2 `frame_3` is `[1, 2, 3, h'a0', null]` (an empty `PAIR_REQUEST` map, unsigned) and
`frame_4`'s body is `{0: h'705f…', 1: "golden-host"}`; `th_3` of that vector is the SAS input
and renders as `346 695`.

The host signs with ed25519-dalek from the seed; the unit test
`transcript::tests::expanded_keypair_signs_identically` proves Arti's `ExpandedKeypair`
built from the same seed produces byte-identical signatures (decision M1-11), so the vectors
hold for a host whose key lives in Arti's keystore too.

## Fuzz seeds

`fuzz/seeds/envelope/<scenario>.bin` = the scenario byte (`fsm::harness::Scenario::byte`:
bit 0 re-sign, bit 1 paired, bit 2 client role) followed by the scenario's frames as
`u16`-BE length-prefixed payloads (the envelope bytes without the `u32` wire prefix): the
vector's client frames for the host scenarios, its host frames for the client scenarios, then
a `PING{nonce: 1}` (client → host) or `PONG{nonce: 0x3333333333333333}` (host → client, the
client's scripted `PING` nonce) and a `BYE{USER}`. Every seed drives its FSM to an established
session; `TORNECT_UPDATE_SEEDS=1 cargo test -p tornect-signal fuzz_seeds` rewrites them.
