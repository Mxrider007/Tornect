//! The B.8.4.3 golden vectors (decision M1-10, `docs/notes/m1-golden-vector.md`):
//! fixed seeds and nonces ([`super::vectors`]) ⇒ exact wire frames, `th_i`,
//! digests, signatures and — for the unpaired exchange — the SAS.
//!
//! * Vector 1: `HELLO → HELLO_ACK → SESSION_REQUEST → SESSION_ACCEPT` with an
//!   already paired device.
//! * Vector 2: the same with an unpaired device, so `PAIR_REQUEST` /
//!   `PAIR_ACCEPT` and `th_after(PAIR_REQUEST)` (the SAS input) are pinned.
//!
//! Any change to the envelope encoding, the body key numbering, the
//! transcript or the signature input changes these bytes; regenerate the note
//! together with the test and record why.

use std::sync::Arc;

use tokio::io::duplex;
use tornect_core::trusted::TrustedDevices;

use super::harness::{self, Role, Scenario};
use super::host::{HostDeps, HostOutcome, serve_host};
use super::vectors::{
    self, CLIENT_NONCE, CLIENT_SAS_NONCE, SESSION_TOKEN, client_config, client_identity,
    host_config, host_device_pk, host_identity, host_random,
};
use super::*;
use crate::envelope::Kind;
use crate::messages::{Bye, Hello, PairRequest, Ping, Pong, SessionRequest, bye};
use crate::pairing::{
    PairDecision, PairScript, Sas, ScriptedConsent, SessionDecision, SessionScript,
    TrustedDeviceStore,
};
use crate::transcript::{HostSigner, digest};

/// Vector 1: `(label, hex)` pairs in the order the note lists them.
const EXPECTED_PAIRED: &[(&str, &str)] = &[
    (
        "host_pk",
        "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
    ),
    (
        "client_pk",
        "a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0",
    ),
    (
        "host_device_pk",
        "705fbac01f5519899f437bc42e40255ae9ab54bff00de3433af7d687d9e71ad5",
    ),
    (
        "th_0",
        "8cc466fe5dfebdc9b12920ad7bcd2de8ee6155a4ac9737101cee047b1ab19a0f",
    ),
    (
        "frame_1_hello",
        "000000cb850101015883a700010158203333333333333333333333333333333333333333333333333333333333333333025820a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0036d676f6c64656e2d636c69656e740481637561310601075820296dd693a5985d2ea73a29506b6b3f658da4caccfa74604caf02547dceddf53258409a560771005f1bee0218f1d0d632f8ba396101d425f841b2a97c8559f30c11ab607971bc741b6fb739ba7e458a90aba9c64b21f45a1d7aec18e86118981b800d",
    ),
    (
        "digest_1",
        "ad9b9ba0dbe8c54c9a74e3c3f9a17957ed03419af043c302e795f6a86dd28e90",
    ),
    (
        "sig_1",
        "9a560771005f1bee0218f1d0d632f8ba396101d425f841b2a97c8559f30c11ab607971bc741b6fb739ba7e458a90aba9c64b21f45a1d7aec18e86118981b800d",
    ),
    (
        "th_1",
        "8caef2e1a45b6709a11e6b77e30f1e76181b523d18456f0e7f86079e737dc5cd",
    ),
    (
        "frame_2_hello_ack",
        "0000007485010102582ca30001015820444444444444444444444444444444444444444444444444444444444444444402816375613158403f7334b1e851f3782f9567761a590fb72de251ff49100e5006d4797b5e27b930b34d7ccb68b3ed876ebd566c88dc1e5343f91b22e08311dd2a7ab1b537348300",
    ),
    (
        "digest_2",
        "87fbc62c64df8998566f919714fe3c8c2132737d56166b9c95dcf4e5ce98acd0",
    ),
    (
        "sig_2",
        "3f7334b1e851f3782f9567761a590fb72de251ff49100e5006d4797b5e27b930b34d7ccb68b3ed876ebd566c88dc1e5343f91b22e08311dd2a7ab1b537348300",
    ),
    (
        "th_2",
        "7220217c64f3ab99ecb74bd0b4b71c0fab91af0a48728595c15cca04e533bb5b",
    ),
    (
        "frame_3_session_request",
        "0000005d8501020656a100a400816468323634018219078019043802f403015840942dc211f5c87a941a3858e11fee803327a871a9feddaf412770f99b7f53642b31617fa524dd46a56406e4a96c741136dd85527cac873297da66f1c360607806",
    ),
    (
        "digest_3",
        "832201e56df8eef50c7d96bf2b5574d1cb32f3aa932f90d4b82dd58379fac3cb",
    ),
    (
        "sig_3",
        "942dc211f5c87a941a3858e11fee803327a871a9feddaf412770f99b7f53642b31617fa524dd46a56406e4a96c741136dd85527cac873297da66f1c360607806",
    ),
    (
        "th_3",
        "25be6b10f9d169246d4ca80492836e7e9312b8d8bc05d44f7d67bb38ab70ae1c",
    ),
    (
        "frame_4_session_accept",
        "000000ba850102075872a800a400816468323634018219078019043802f4030101582c302a300506032b6570032100705fbac01f5519899f437bc42e40255ae9ab54bff00de3433af7d687d9e71ad50200030004000558205555555555555555555555555555555555555555555555555555555555555555070008f45840397ca281efacd130ce458ed6aa24dd882ffcc938ed6362ba6a4118da04a0e7e6f6fd6eb15a2f01b55ce94cdc58d93fd364ba640e40edfbeb21717392548e6807",
    ),
    (
        "digest_4",
        "728405e008449e172d395bfc2133f7098a88a1d61032d3e851eabfec023b98d4",
    ),
    (
        "sig_4",
        "397ca281efacd130ce458ed6aa24dd882ffcc938ed6362ba6a4118da04a0e7e6f6fd6eb15a2f01b55ce94cdc58d93fd364ba640e40edfbeb21717392548e6807",
    ),
    (
        "th_4",
        "c83e71f2449432f86fb11be72ced679d40e664a4c7ba0694f0eb7a43f2ab939e",
    ),
];

/// Vector 2: the unpaired exchange (`PAIR_REQUEST` / `PAIR_ACCEPT`, the SAS).
const EXPECTED_UNPAIRED: &[(&str, &str)] = &[
    (
        "host_pk",
        "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
    ),
    (
        "client_pk",
        "a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0",
    ),
    (
        "host_device_pk",
        "705fbac01f5519899f437bc42e40255ae9ab54bff00de3433af7d687d9e71ad5",
    ),
    (
        "th_0",
        "8cc466fe5dfebdc9b12920ad7bcd2de8ee6155a4ac9737101cee047b1ab19a0f",
    ),
    (
        "frame_1_hello",
        "000000cb850101015883a700010158203333333333333333333333333333333333333333333333333333333333333333025820a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0036d676f6c64656e2d636c69656e740481637561310600075820296dd693a5985d2ea73a29506b6b3f658da4caccfa74604caf02547dceddf5325840d18a011e6924117a2728b05350d177c1bbad77be981915d421575faa3434ecbf1dc7d813fa11f8a8c32409a52ba6c7b11df4a129256de03af2b251759f712b05",
    ),
    (
        "digest_1",
        "eb5f68ec4282fd463274a9e2f63e9e9150b323c36f63017874e488616dd2456e",
    ),
    (
        "sig_1",
        "d18a011e6924117a2728b05350d177c1bbad77be981915d421575faa3434ecbf1dc7d813fa11f8a8c32409a52ba6c7b11df4a129256de03af2b251759f712b05",
    ),
    (
        "th_1",
        "eae40e02559900e8190d041d768764f1eb98b21d98bec1cf96f9c1434cbcb9df",
    ),
    (
        "frame_2_hello_ack",
        "0000007485010102582ca3000101582044444444444444444444444444444444444444444444444444444444444444440281637561315840354e204f34b22e188d185dd3f87a7453b68fe5416b2b227b648963c6d0ce8f9c0b8b44a1f9744cf26627780e78e27a89f80732340209aaf6249853b53681470c",
    ),
    (
        "digest_2",
        "87fbc62c64df8998566f919714fe3c8c2132737d56166b9c95dcf4e5ce98acd0",
    ),
    (
        "sig_2",
        "354e204f34b22e188d185dd3f87a7453b68fe5416b2b227b648963c6d0ce8f9c0b8b44a1f9744cf26627780e78e27a89f80732340209aaf6249853b53681470c",
    ),
    (
        "th_2",
        "2e2bfdeac4e42898cd34dea06ae17f40bfb2a46dde03995f5f7b15163907b58c",
    ),
    (
        "frame_3_pair_request",
        "0000002b850102035824a10158205a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5af6",
    ),
    (
        "th_3",
        "e5421e5600db4a2936282ba13f56173262422de23d915ef73bb13e62ad820d9b",
    ),
    ("sas", "317 525"),
    (
        "frame_4_pair_accept",
        "00000038850102045831a2005820705fbac01f5519899f437bc42e40255ae9ab54bff00de3433af7d687d9e71ad5016b676f6c64656e2d686f7374f6",
    ),
    (
        "th_4",
        "93c6db94378b836b83e5d1ec64f4208da3f967e4b4dd3c6ae13554d52dcbe618",
    ),
    (
        "frame_5_session_request",
        "0000005d8501030656a100a400816468323634018219078019043802f403015840c094dd6bf87bf5e2ecb26a5913d35623f4ecd659752db9e4d8e7103f14f78d7c8f5fba882b6bded4c07ac1b40236699d5cc4022c543da66a7bbf556fa8bc2404",
    ),
    (
        "digest_5",
        "2b916c1a2542ce973e5c714c7235fc1487e9e0c22c42acd1846da789e2ffc2ff",
    ),
    (
        "sig_5",
        "c094dd6bf87bf5e2ecb26a5913d35623f4ecd659752db9e4d8e7103f14f78d7c8f5fba882b6bded4c07ac1b40236699d5cc4022c543da66a7bbf556fa8bc2404",
    ),
    (
        "th_5",
        "4a16ef2cc358b92cac4b51fe6feac2804baabe878a980eea015d44c3b3889a30",
    ),
    (
        "frame_6_session_accept",
        "000000ba850103075872a800a400816468323634018219078019043802f4030101582c302a300506032b6570032100705fbac01f5519899f437bc42e40255ae9ab54bff00de3433af7d687d9e71ad50200030004000558205555555555555555555555555555555555555555555555555555555555555555070008f45840c91992d9b94120de1c2e9270bb57c86f3abbd4fa8b58b2af683b463cf052191b1123c0eef5bea7b5f20c071f3273abba3177b12ac361f5f4f0a7cb0ebe6a6709",
    ),
    (
        "digest_6",
        "e9d7bbdd0fd5bf991fff4d4a9be1d08f19b43b0c16cb2fef86ffd0b8717c2968",
    ),
    (
        "sig_6",
        "c91992d9b94120de1c2e9270bb57c86f3abbd4fa8b58b2af683b463cf052191b1123c0eef5bea7b5f20c071f3273abba3177b12ac361f5f4f0a7cb0ebe6a6709",
    ),
    (
        "th_6",
        "a28dfc92fa3b1645a1e6afc3b9f3a3db7609efe59ca1dab6eac3b48f6b8ce94d",
    ),
];

/// The client frames a well-behaved client sends, as bodies.
fn client_hello(paired: bool) -> Hello {
    let cfg = client_config(host_identity().id());
    Hello {
        v_max: cfg.v_max,
        client_nonce: CLIENT_NONCE,
        device_pk: HostSigner::public_key(&client_identity()),
        name: cfg.name,
        feats: cfg.feats,
        stop_token: None,
        pairing_state: u8::from(paired),
        sas_commit: crate::pairing::sas_commit(&CLIENT_SAS_NONCE),
    }
}

fn client_request() -> SessionRequest {
    SessionRequest {
        caps: client_config(host_identity().id()).caps,
        unattended: None,
    }
}

/// Run the exchange and return every value of the vector as `(label, hex)`.
pub(super) async fn compute(paired: bool) -> Vec<(&'static str, String)> {
    let host = Arc::new(host_identity());
    let client = client_identity();
    let mut devices = TrustedDevices::default();
    if paired {
        devices.pin(client.id(), vectors::CLIENT_NAME, 1);
    }
    let trusted = Arc::new(TrustedDeviceStore::ephemeral(devices));
    let consent = Arc::new(ScriptedConsent::new());
    consent.push_pairing(PairScript::Decide(PairDecision::Accept { label: None }));
    consent.push_session(SessionScript::Decide(SessionDecision::AllowOnce));
    let mut deps = HostDeps::headless(host.clone(), trusted);
    deps.consent = consent;
    deps.random = host_random();
    let cfg = host_config();

    let (a, b) = duplex(64 * 1024);
    let task = tokio::spawn(async move { serve_host(a, &cfg, &deps).await });
    let host_pk = HostSigner::public_key(&*host);
    let mut chan = Channel::new(b, &host_pk);
    let mut out = vec![
        ("host_pk", hex::encode(host_pk)),
        ("client_pk", hex::encode(HostSigner::public_key(&client))),
        ("host_device_pk", hex::encode(host_device_pk())),
        ("th_0", hex::encode(chan.th())),
    ];

    fn record(
        out: &mut Vec<(&'static str, String)>,
        labels: &'static [&'static str],
        payload: &[u8],
        th: [u8; 32],
    ) {
        let env = Envelope::decode(payload).unwrap();
        out.push((labels[0], hex::encode(wire_bytes(payload))));
        if env.kind.is_signed() {
            out.push((
                labels[1],
                hex::encode(digest(env.v, env.msg_id, env.kind, &env.body)),
            ));
            out.push((labels[2], hex::encode(env.sig.expect("signed"))));
        }
        out.push((labels[3], hex::encode(th)));
    }

    let hello = chan
        .send(&client_hello(paired), Some(&client))
        .await
        .unwrap();
    record(
        &mut out,
        &["frame_1_hello", "digest_1", "sig_1", "th_1"],
        &hello,
        chan.th(),
    );
    let ack = chan
        .recv(Duration::from_secs(5), "ack")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ack.env.kind, Kind::HelloAck);
    chan.absorb(&ack);
    chan.set_version(1);
    // th_after(HELLO_ACK) — the SAS input of §B.3.
    let th_hello_ack = chan.th();
    record(
        &mut out,
        &["frame_2_hello_ack", "digest_2", "sig_2", "th_2"],
        &ack.wire[4..],
        chan.th(),
    );
    let mut i = 2;
    if !paired {
        let pair_request = chan
            .send(
                &PairRequest {
                    sas_nonce: CLIENT_SAS_NONCE,
                    ..PairRequest::default()
                },
                None,
            )
            .await
            .unwrap();
        record(
            &mut out,
            &["frame_3_pair_request", "", "", "th_3"],
            &pair_request,
            chan.th(),
        );
        out.push((
            "sas",
            Sas::derive(&th_hello_ack, &CLIENT_SAS_NONCE).render(),
        ));
        let pair_accept = chan
            .recv(Duration::from_secs(5), "pair accept")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(pair_accept.env.kind, Kind::PairAccept);
        chan.absorb(&pair_accept);
        record(
            &mut out,
            &["frame_4_pair_accept", "", "", "th_4"],
            &pair_accept.wire[4..],
            chan.th(),
        );
        i = 4;
    }
    let request = chan.send(&client_request(), Some(&client)).await.unwrap();
    let request_labels: &'static [&'static str] = if i == 2 {
        &["frame_3_session_request", "digest_3", "sig_3", "th_3"]
    } else {
        &["frame_5_session_request", "digest_5", "sig_5", "th_5"]
    };
    record(&mut out, request_labels, &request, chan.th());
    let accept = chan
        .recv(Duration::from_secs(5), "accept")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(accept.env.kind, Kind::SessionAccept);
    chan.absorb(&accept);
    let accept_labels: &'static [&'static str] = if i == 2 {
        &["frame_4_session_accept", "digest_4", "sig_4", "th_4"]
    } else {
        &["frame_6_session_accept", "digest_6", "sig_6", "th_6"]
    };
    record(&mut out, accept_labels, &accept.wire[4..], chan.th());
    chan.bye(bye::USER).await.unwrap();
    match task.await.unwrap().unwrap() {
        HostOutcome::Session {
            th_final,
            token,
            paired_now,
            ..
        } => {
            assert_eq!(th_final, chan.th());
            assert_eq!(token.bytes(), &SESSION_TOKEN);
            assert_eq!(paired_now, !paired);
        }
        other => panic!("{other:?}"),
    }
    out
}

fn check(actual: &[(&str, String)], expected: &[(&str, &str)]) {
    let rendered: Vec<String> = actual.iter().map(|(k, v)| format!("{k} = {v}")).collect();
    assert_eq!(
        actual.len(),
        expected.len(),
        "vector length changed; full vector:\n{}",
        rendered.join("\n")
    );
    for ((label, hex), (elabel, ehex)) in actual.iter().zip(expected) {
        assert_eq!(label, elabel);
        assert_eq!(
            hex,
            ehex,
            "{label} changed; full vector:\n{}",
            rendered.join("\n")
        );
    }
}

#[tokio::test]
async fn golden_vector_attended_exchange() {
    let actual = compute(true).await;
    check(&actual, EXPECTED_PAIRED);
    // Deterministic across runs.
    let again = compute(true).await;
    assert_eq!(actual, again);
}

#[tokio::test]
async fn golden_vector_pairing_exchange() {
    let actual = compute(false).await;
    check(&actual, EXPECTED_UNPAIRED);
    let again = compute(false).await;
    assert_eq!(actual, again);
}

/// Where the committed fuzz seeds live (`cargo +nightly fuzz run envelope
/// target/fuzz-corpus/envelope fuzz/seeds/envelope`).
const SEED_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fuzz/seeds/envelope");

fn frame_payload(vector: &[(&str, String)], label: &str) -> Vec<u8> {
    let hex = &vector.iter().find(|(k, _)| *k == label).expect(label).1;
    // The vector lists wire frames (u32-BE length prefix); the harness takes payloads.
    hex::decode(hex).unwrap()[4..].to_vec()
}

fn unsigned(msg_id: u64, kind: Kind, body: Vec<u8>) -> Vec<u8> {
    Envelope::new(1, msg_id, kind, body).encode()
}

/// The seed of every harness scenario: the recorded handshake frames of the
/// vector plus a `PING` / `PONG` and a `BYE` for the established state.
async fn seeds() -> Vec<(Scenario, Vec<u8>)> {
    let paired = compute(true).await;
    let unpaired = compute(false).await;
    let ping = |id| unsigned(id, Kind::Ping, encode_body(&Ping { nonce: 1 }));
    let pong_nonce = u64::from_be_bytes(CLIENT_NONCE[..8].try_into().unwrap());
    let pong = |id| unsigned(id, Kind::Pong, encode_body(&Pong { nonce: pong_nonce }));
    let goodbye = |id| {
        unsigned(
            id,
            Kind::Bye,
            encode_body(&Bye {
                reason: bye::USER,
                detail: None,
            }),
        )
    };
    Scenario::all()
        .into_iter()
        .map(|s| {
            let frames: Vec<Vec<u8>> = match (s.role, s.paired) {
                (Role::Host, true) => vec![
                    frame_payload(&paired, "frame_1_hello"),
                    frame_payload(&paired, "frame_3_session_request"),
                    ping(3),
                    goodbye(4),
                ],
                (Role::Host, false) => vec![
                    frame_payload(&unpaired, "frame_1_hello"),
                    frame_payload(&unpaired, "frame_3_pair_request"),
                    frame_payload(&unpaired, "frame_5_session_request"),
                    ping(4),
                    goodbye(5),
                ],
                (Role::Client, true) => vec![
                    frame_payload(&paired, "frame_2_hello_ack"),
                    frame_payload(&paired, "frame_4_session_accept"),
                    pong(3),
                    goodbye(4),
                ],
                (Role::Client, false) => vec![
                    frame_payload(&unpaired, "frame_2_hello_ack"),
                    frame_payload(&unpaired, "frame_4_pair_accept"),
                    frame_payload(&unpaired, "frame_6_session_accept"),
                    pong(4),
                    goodbye(5),
                ],
            };
            let mut bytes = vec![s.byte()];
            bytes.extend(harness::join_frames(frames.iter().map(Vec::as_slice)));
            (s, bytes)
        })
        .collect()
}

/// The committed seeds equal the vectors (`TORNECT_UPDATE_SEEDS=1` rewrites
/// them), and each one drives its scenario all the way to an established
/// session — the coverage the F1 target claims.
#[tokio::test(start_paused = true)]
async fn fuzz_seeds_match_the_golden_vectors_and_reach_a_session() {
    let update = std::env::var_os("TORNECT_UPDATE_SEEDS").is_some();
    if update {
        std::fs::create_dir_all(SEED_DIR).unwrap();
    }
    for (scenario, bytes) in seeds().await {
        let path = std::path::Path::new(SEED_DIR).join(format!("{}.bin", scenario.name()));
        if update {
            std::fs::write(&path, &bytes).unwrap();
        }
        let on_disk = std::fs::read(&path).unwrap_or_else(|e| {
            panic!("{}: {e} (run with TORNECT_UPDATE_SEEDS=1)", path.display())
        });
        assert_eq!(on_disk, bytes, "{} is stale", path.display());
        let frames = harness::split_frames(&bytes[1..]);
        let outcome = harness::run(scenario, frames).await;
        assert!(outcome.established(), "{scenario:?}: {outcome:?}");
    }
}
