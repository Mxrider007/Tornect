# M1 golden vectors — envelope / transcript / signatures / SAS (docs/PLAN.md §B.8.4.3)

Decision M1-10. Pinned by the unit tests `fsm::golden::golden_vector_attended_exchange`
(vector 1), `fsm::golden::golden_vector_pairing_exchange` (vector 2),
`fsm::golden::golden_vector_administrator_accept` (vector 3) and
`fsm::golden::golden_vector_unattended_request_bodies` (the `want_elevation` bodies) in
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
sas_commit = SHA-256("tornect/v1/sas-commit\0" || sas_nonce)                 // published in HELLO (signed)
SAS = u32::from_be_bytes(HKDF-SHA256(ikm = th_after(HELLO_ACK) || sas_nonce, salt = "tornect/v1/sas", info = "sas-v1")[0..4]) % 1_000_000
```

## Vector 1 — paired device (`HELLO → HELLO_ACK → SESSION_REQUEST → SESSION_ACCEPT`)

| # | Value | Hex |
|---|---|---|
| 0 | `th_0` | `8cc466fe5dfebdc9b12920ad7bcd2de8ee6155a4ac9737101cee047b1ab19a0f` |
| 1 | `frame_1_hello` (`HELLO`, client, msg_id 1) | `000000cb850101015883a700010158203333333333333333333333333333333333333333333333333333333333333333025820a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0036d676f6c64656e2d636c69656e740481637561310601075820296dd693a5985d2ea73a29506b6b3f658da4caccfa74604caf02547dceddf53258409a560771005f1bee0218f1d0d632f8ba396101d425f841b2a97c8559f30c11ab607971bc741b6fb739ba7e458a90aba9c64b21f45a1d7aec18e86118981b800d` |
| 1 | `digest_1` | `ad9b9ba0dbe8c54c9a74e3c3f9a17957ed03419af043c302e795f6a86dd28e90` |
| 1 | `sig_1` (client device key, over `th_0`) | `9a560771005f1bee0218f1d0d632f8ba396101d425f841b2a97c8559f30c11ab607971bc741b6fb739ba7e458a90aba9c64b21f45a1d7aec18e86118981b800d` |
| 1 | `th_1` | `8caef2e1a45b6709a11e6b77e30f1e76181b523d18456f0e7f86079e737dc5cd` |
| 2 | `frame_2_hello_ack` (`HELLO_ACK`, host, msg_id 1) | `0000007485010102582ca30001015820444444444444444444444444444444444444444444444444444444444444444402816375613158403f7334b1e851f3782f9567761a590fb72de251ff49100e5006d4797b5e27b930b34d7ccb68b3ed876ebd566c88dc1e5343f91b22e08311dd2a7ab1b537348300` |
| 2 | `digest_2` | `87fbc62c64df8998566f919714fe3c8c2132737d56166b9c95dcf4e5ce98acd0` |
| 2 | `sig_2` (host onion key, over `th_1`) | `3f7334b1e851f3782f9567761a590fb72de251ff49100e5006d4797b5e27b930b34d7ccb68b3ed876ebd566c88dc1e5343f91b22e08311dd2a7ab1b537348300` |
| 2 | `th_2` | `7220217c64f3ab99ecb74bd0b4b71c0fab91af0a48728595c15cca04e533bb5b` |
| 3 | `frame_3_session_request` (`SESSION_REQUEST`, client, msg_id 2) | `0000005d8501020656a100a400816468323634018219078019043802f403015840942dc211f5c87a941a3858e11fee803327a871a9feddaf412770f99b7f53642b31617fa524dd46a56406e4a96c741136dd85527cac873297da66f1c360607806` |
| 3 | `digest_3` | `832201e56df8eef50c7d96bf2b5574d1cb32f3aa932f90d4b82dd58379fac3cb` |
| 3 | `sig_3` (client device key, over `th_2`) | `942dc211f5c87a941a3858e11fee803327a871a9feddaf412770f99b7f53642b31617fa524dd46a56406e4a96c741136dd85527cac873297da66f1c360607806` |
| 3 | `th_3` | `25be6b10f9d169246d4ca80492836e7e9312b8d8bc05d44f7d67bb38ab70ae1c` |
| 4 | `frame_4_session_accept` (`SESSION_ACCEPT`, host, msg_id 2) | `000000ba850102075872a800a400816468323634018219078019043802f4030101582c302a300506032b6570032100705fbac01f5519899f437bc42e40255ae9ab54bff00de3433af7d687d9e71ad50200030004000558205555555555555555555555555555555555555555555555555555555555555555070008f45840397ca281efacd130ce458ed6aa24dd882ffcc938ed6362ba6a4118da04a0e7e6f6fd6eb15a2f01b55ce94cdc58d93fd364ba640e40edfbeb21717392548e6807` |
| 4 | `digest_4` | `728405e008449e172d395bfc2133f7098a88a1d61032d3e851eabfec023b98d4` |
| 4 | `sig_4` (host onion key, over `th_3`) | `397ca281efacd130ce458ed6aa24dd882ffcc938ed6362ba6a4118da04a0e7e6f6fd6eb15a2f01b55ce94cdc58d93fd364ba640e40edfbeb21717392548e6807` |
| 4 | `th_4` (`th_final`, identical on both sides) | `c83e71f2449432f86fb11be72ced679d40e664a4c7ba0694f0eb7a43f2ab939e` |

## Vector 2 — unpaired device (`HELLO → HELLO_ACK → PAIR_REQUEST → PAIR_ACCEPT → SESSION_REQUEST → SESSION_ACCEPT`)

| # | Value | Hex |
|---|---|---|
| 0 | `th_0` | `8cc466fe5dfebdc9b12920ad7bcd2de8ee6155a4ac9737101cee047b1ab19a0f` |
| 1 | `frame_1_hello` (`HELLO`, client, msg_id 1, `pairing_state = 0`) | `000000cb850101015883a700010158203333333333333333333333333333333333333333333333333333333333333333025820a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0036d676f6c64656e2d636c69656e740481637561310600075820296dd693a5985d2ea73a29506b6b3f658da4caccfa74604caf02547dceddf5325840d18a011e6924117a2728b05350d177c1bbad77be981915d421575faa3434ecbf1dc7d813fa11f8a8c32409a52ba6c7b11df4a129256de03af2b251759f712b05` |
| 1 | `digest_1` | `eb5f68ec4282fd463274a9e2f63e9e9150b323c36f63017874e488616dd2456e` |
| 1 | `sig_1` (client device key, over `th_0`) | `d18a011e6924117a2728b05350d177c1bbad77be981915d421575faa3434ecbf1dc7d813fa11f8a8c32409a52ba6c7b11df4a129256de03af2b251759f712b05` |
| 1 | `th_1` | `eae40e02559900e8190d041d768764f1eb98b21d98bec1cf96f9c1434cbcb9df` |
| 2 | `frame_2_hello_ack` (`HELLO_ACK`, host, msg_id 1) | `0000007485010102582ca3000101582044444444444444444444444444444444444444444444444444444444444444440281637561315840354e204f34b22e188d185dd3f87a7453b68fe5416b2b227b648963c6d0ce8f9c0b8b44a1f9744cf26627780e78e27a89f80732340209aaf6249853b53681470c` |
| 2 | `digest_2` | `87fbc62c64df8998566f919714fe3c8c2132737d56166b9c95dcf4e5ce98acd0` |
| 2 | `sig_2` (host onion key, over `th_1`) | `354e204f34b22e188d185dd3f87a7453b68fe5416b2b227b648963c6d0ce8f9c0b8b44a1f9744cf26627780e78e27a89f80732340209aaf6249853b53681470c` |
| 2 | `th_2` | `2e2bfdeac4e42898cd34dea06ae17f40bfb2a46dde03995f5f7b15163907b58c` |
| 3 | `frame_3_pair_request` (`PAIR_REQUEST`, client, msg_id 2, unsigned) | `0000002b850102035824a10158205a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5af6` |
| 3 | `th_3` = `th_after(PAIR_REQUEST)` (chain only; **not** the SAS input, M1-37) | `e5421e5600db4a2936282ba13f56173262422de23d915ef73bb13e62ad820d9b` |
| 3 | `sas` (rendered) | `317 525` |
| 4 | `frame_4_pair_accept` (`PAIR_ACCEPT`, host, msg_id 2, unsigned) | `00000038850102045831a2005820705fbac01f5519899f437bc42e40255ae9ab54bff00de3433af7d687d9e71ad5016b676f6c64656e2d686f7374f6` |
| 4 | `th_4` | `93c6db94378b836b83e5d1ec64f4208da3f967e4b4dd3c6ae13554d52dcbe618` |
| 5 | `frame_5_session_request` (`SESSION_REQUEST`, client, msg_id 3) | `0000005d8501030656a100a400816468323634018219078019043802f403015840c094dd6bf87bf5e2ecb26a5913d35623f4ecd659752db9e4d8e7103f14f78d7c8f5fba882b6bded4c07ac1b40236699d5cc4022c543da66a7bbf556fa8bc2404` |
| 5 | `digest_5` | `2b916c1a2542ce973e5c714c7235fc1487e9e0c22c42acd1846da789e2ffc2ff` |
| 5 | `sig_5` (client device key, over `th_4`) | `c094dd6bf87bf5e2ecb26a5913d35623f4ecd659752db9e4d8e7103f14f78d7c8f5fba882b6bded4c07ac1b40236699d5cc4022c543da66a7bbf556fa8bc2404` |
| 5 | `th_5` | `4a16ef2cc358b92cac4b51fe6feac2804baabe878a980eea015d44c3b3889a30` |
| 6 | `frame_6_session_accept` (`SESSION_ACCEPT`, host, msg_id 3) | `000000ba850103075872a800a400816468323634018219078019043802f4030101582c302a300506032b6570032100705fbac01f5519899f437bc42e40255ae9ab54bff00de3433af7d687d9e71ad50200030004000558205555555555555555555555555555555555555555555555555555555555555555070008f45840c91992d9b94120de1c2e9270bb57c86f3abbd4fa8b58b2af683b463cf052191b1123c0eef5bea7b5f20c071f3273abba3177b12ac361f5f4f0a7cb0ebe6a6709` |
| 6 | `digest_6` | `e9d7bbdd0fd5bf991fff4d4a9be1d08f19b43b0c16cb2fef86ffd0b8717c2968` |
| 6 | `sig_6` (host onion key, over `th_5`) | `c91992d9b94120de1c2e9270bb57c86f3abbd4fa8b58b2af683b463cf052191b1123c0eef5bea7b5f20c071f3273abba3177b12ac361f5f4f0a7cb0ebe6a6709` |
| 6 | `th_6` (`th_final`, identical on both sides) | `a28dfc92fa3b1645a1e6afc3b9f3a3db7609efe59ca1dab6eac3b48f6b8ce94d` |

## Vector 3 — the session levels (r7, §B.2.1, §B.8.4.1; M-FEAT-2)

Vector 1 on a host whose availability row offers the administrator answer (an invented Windows host: installed,
an administrator account, `EnableLUA` 0), answered "Allow as administrator" (`SessionDecision::AllowOnceAdmin`).
Frames 1–3, their digests, signatures and `th_1…th_3` are vector 1's, byte for byte (the test checks them against
vector 1's table); only the accept changes: its body gains key 11, `elevation = 1`, inside the signed body
(`digest_4` covers it, so does `sig_4`).

| # | Value | Hex |
|---|---|---|
| 4 | `frame_4_session_accept` (`SESSION_ACCEPT`, host, msg_id 2) | `000000bc850102075874a900a400816468323634018219078019043802f4030101582c302a300506032b6570032100705fbac01f5519899f437bc42e40255ae9ab54bff00de3433af7d687d9e71ad50200030004000558205555555555555555555555555555555555555555555555555555555555555555070008f40b0158403e1780fc3b649494cb142fc9fe526d8f073038fe769ff0ca6788e812583e8d7fa886579125c00009015ee8e9b958310fbfbdfc46fa6f2f50c3f2184c611f8006` |
| 4 | `digest_4` | `e6182a5859ce71719d9de07ab89256903a89906fd67e681aa8953e72530bb93d` |
| 4 | `sig_4` (host onion key, over `th_3`) | `3e1780fc3b649494cb142fc9fe526d8f073038fe769ff0ca6788e812583e8d7fa886579125c00009015ee8e9b958310fbfbdfc46fa6f2f50c3f2184c611f8006` |
| 4 | `th_4` (`th_final`) | `f3142b4f965ad0c47cc074f244efe5237a461acf080c4199850d91b69e0bc9ac` |

The body reads as vector 1's with one more entry: the map header `a9` (nine entries, `a8` in vector 1) and
`… 07 00 08 f4 0b 01`: key 7 `0`, key 8 `false`, key 11 `1`. An accept at none carries no key 11, so vectors 1 and 2
are unchanged, and `fsm::golden::the_old_vectors_decode_at_none` decodes them with this build (elevation none; the
attended request has no `unattended` map).

**`SESSION_REQUEST.unattended.want_elevation` (key 5).** Two unattended request bodies with the vector's client caps,
`suite` 1, the fixed `ke1` `66` × 96, `want_mode` 0, `intent` 0, and each body's digest as the second frame of a stream
(`v` 1, `msg_id` 2, kind 6). No signature: an unattended exchange runs the PAKE, whose randomness these vectors do not
fix; the digest is what the client's signature covers.

| Value | Hex |
|---|---|
| body without `want_elevation` | `a200a400816468323634018219078019043802f4030101a4000101586066666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666602000300` |
| its digest | `fa226454f87515cdd417e38f9f939ffc363efd369935426a1f190dc314872ba2` |
| body with `want_elevation = 1` | `a200a400816468323634018219078019043802f4030101a50001015860666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666666020003000501` |
| its digest | `6a9d583d98407e7808e4962029ec1ef51c54f61ac1953d363b77c26aec347fd6` |

The unattended map goes from four entries (`a4`) to five (`a5`), and `05 01` (key 5, value 1) is appended; nothing
else moves.

**Compatibility.** Bodies are CBOR maps and receivers ignore unknown keys (§B.8.4.1): a client built before r7 decodes
vector 3's accept and never sees key 11 (the host's indicator, not that client's HUD, is then the authority for the
person at the computer), and a host built before r7 decodes a request with key 5 as if it were absent.
`messages::tests::a_peer_before_the_keys_ignores_them` decodes both new bodies into the pre-r7 map types. Decoding
here refuses `elevation` or `want_elevation` other than 0 or 1, and `elevation = 1` unless `mode = 0`
(`messages::tests::the_elevation_keys_decode_only_in_their_domain`).

## Vectors 4 to 10 — `grant_reach` (decision M1-67)

The unattended answers carry the signed key `grant_reach` (§B.8.4.1): key 12 of `SESSION_ACCEPT`, key 2 of
`ADMIN_RESULT`; 0 none, 1 reach through the host, 2 the grant holds the administrator level. Each vector is a body and
its digest as the host's third frame of a stream (`v` 1, `msg_id` 3: `HELLO_ACK`, `AUTH_CHALLENGE`, then the answer;
kind 7 for `SESSION_ACCEPT`, 11 for `ADMIN_RESULT`). No signature: an unattended exchange runs the PAKE, whose
randomness these vectors do not fix; the digest is what the host's signature covers. The accepts use vector 1's
negotiated caps and host device key, `session_type` 1, `transport_policy` 0, `token_confirm` `77` × 32 (no
`session_token`), `block_window_s` 0 and `ask_before_start` false (`fsm::golden::golden_vector_unattended_answers_4_to_10`).

| Vector | Value | Hex |
|---|---|---|
| 4 | `SESSION_ACCEPT`, control, `elevation` absent, `grant_reach` 0 | `a900a400816468323634018219078019043802f4030101582c302a300506032b6570032100705fbac01f5519899f437bc42e40255ae9ab54bff00de3433af7d687d9e71ad50201030004000658207777777777777777777777777777777777777777777777777777777777777777070008f40c00` |
| 4 | its digest | `da2cd532ecef91b0a851e3f036497b60c6de0dc9e8d9b1edfc9e98b940fdaba6` |
| 5 | the same at `grant_reach` 1 | `a900a400816468323634018219078019043802f4030101582c302a300506032b6570032100705fbac01f5519899f437bc42e40255ae9ab54bff00de3433af7d687d9e71ad50201030004000658207777777777777777777777777777777777777777777777777777777777777777070008f40c01` |
| 5 | its digest | `78942f3bd5dd918d6caef0f1314c6e8005f669bdccf8ee7b6a0a3666f24154dc` |
| 6 | control, `elevation` 1, `grant_reach` 2 | `aa00a400816468323634018219078019043802f4030101582c302a300506032b6570032100705fbac01f5519899f437bc42e40255ae9ab54bff00de3433af7d687d9e71ad50201030004000658207777777777777777777777777777777777777777777777777777777777777777070008f40b010c02` |
| 6 | its digest | `a568228f81b3ec3e1ba30689d4ef00a11eb27ac453d6c87ac6e2a1c9b45be850` |
| 7 | view only, `grant_reach` 2 | `a900a400816468323634018219078019043802f4030101582c302a300506032b6570032100705fbac01f5519899f437bc42e40255ae9ab54bff00de3433af7d687d9e71ad50201030104000658207777777777777777777777777777777777777777777777777777777777777777070008f40c02` |
| 7 | its digest | `6420412b318e1c298a810358207e0d65f8934c19fda6af62580ded3e7059dcc6` |
| 8 | control, `elevation` absent, `grant_reach` 2 | `a900a400816468323634018219078019043802f4030101582c302a300506032b6570032100705fbac01f5519899f437bc42e40255ae9ab54bff00de3433af7d687d9e71ad50201030004000658207777777777777777777777777777777777777777777777777777777777777777070008f40c02` |
| 8 | its digest | `28366a3c3dedc21d303ed903ad6ecf730d6c5672b520a741ae9f3d5db0b6e38f` |
| 9 | `ADMIN_RESULT{ok: true, grant_reach: 0}` | `a200f50200` |
| 9 | its digest | `a6e8b11651fe369fd3acb8d46c2a6cea5496da641fbb62ad9cf323a2cb8ddff5` |
| 10 | `ADMIN_RESULT{ok: false, detail: "unknown admin command", grant_reach: 1}` | `a300f40175756e6b6e6f776e2061646d696e20636f6d6d616e640201` |
| 10 | its digest | `16f22970a64551bd77d0b356a4a3a2cc9d6645396aa389e6e8860044c8525e37` |

An accept body ends `… 07 00 08 f4 0c <reach>` (key 7 `0`, key 8 `false`, key 12), and vector 6 `… 0b 01 0c 02`
(key 11 `1` before key 12); the map has nine entries (`a9`), ten for vector 6 (`aa`). Vectors 1 to 3 are unchanged: an
attended accept never carries key 12, and decoding refuses one that does. Decoding also refuses a `grant_reach` above 2
in either body, and an unattended accept that signs `elevation = 1` with `grant_reach` other than 2
(`messages::tests::a23_grant_reach_decodes_only_in_its_domain`); a duplicated key 12 reads the last value and CBOR null
reads as absent (`messages::tests::a23_a_duplicated_grant_reach_reads_the_last_and_null_reads_absent`). A client
built before the key decodes these bodies and ignores key 12. The fuzz seeds below come from vectors 1 and 2 and are
unchanged.

## Vector 11 — PONG with a notice (M-UI-4)

The host's `PONG` carries key 1, `notice` (decision M1-70, §B.8.4.1): one byte of bits, never text, from which the
viewer says its own fixed sentences (0x01 the host runs Windows, 0x02 the session is not at the administrator level on
a Windows host, so its input cannot reach administrator windows, 0x04 a secure Windows screen is showing; other bits
reserved, kept as received and ignored). The host of a Control session sends it in its first `PONG`, 0 included, and
again only when it changes; every other `PONG` is the plain one. The vector is the body of
`HostPong{nonce: 1, notice: 3}` and its envelope as the host's fourth frame of a stream (`v` 1, `msg_id` 4, kind 16
`PONG`, unsigned; the envelope without the frame's `u32` length prefix) (`fsm::golden::golden_vector_pong_notice`).

| Value | Hex |
|---|---|
| body | `a200010103` |
| envelope | `8501041045a200010103f6` |

The body is the map `{0: 1, 1: 3}`. With no notice the key is absent and the body is `a10001`, byte for byte a plain
`PONG{nonce: 1}` (`fsm::golden::a_pong_without_a_notice_has_the_old_bytes`). A peer built before the key decodes
vector 11 as `PONG{nonce: 1}` and never sees key 1 (`fsm::golden::an_old_pong_decoder_ignores_the_notice`). Vectors 1
to 10 and the fuzz seeds below are unchanged.

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
