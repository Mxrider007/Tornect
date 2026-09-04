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
    self, CLIENT_NONCE, SESSION_TOKEN, client_config, client_identity, host_config, host_device_pk,
    host_identity, host_random,
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
        concat!(
            "000000a8850101015860a6000101582033333333333333333333333333333333",
            "33333333333333333333333333333333025820a09aa5f47a6759802ff955f8dc",
            "2d2a14a5c99d23be97f864127ff9383455a4f0036d676f6c64656e2d636c6965",
            "6e74048163756131060158408c042e6af9dec69da1574ad709fa6f80355c796b",
            "fd54454ab0dada974ac968e4d36a8e98fc339d8ee4b5525bab3411c70b696fe9",
            "1c83add63c30163952308407",
        ),
    ),
    (
        "digest_1",
        "42cdaa1c8f0d516921d909220ae83fd0ce893aa130dd3836c94e65aceda82290",
    ),
    (
        "sig_1",
        concat!(
            "8c042e6af9dec69da1574ad709fa6f80355c796bfd54454ab0dada974ac968e4",
            "d36a8e98fc339d8ee4b5525bab3411c70b696fe91c83add63c30163952308407",
        ),
    ),
    (
        "th_1",
        "12e5f2ef93eddf1fa66d21bfd57a7a5d7ab440393afa15c985f0a96638c98443",
    ),
    (
        "frame_2_hello_ack",
        concat!(
            "0000007485010102582ca3000101582044444444444444444444444444444444",
            "4444444444444444444444444444444402816375613158409a2a86ae7b26c080",
            "d2e1ed51c5b29bb29947423548503fba15cb25e261fa792da5df9b8d10d19993",
            "a3d5c6f2a7055bb836101a40f7acca5c67bf590298143108",
        ),
    ),
    (
        "digest_2",
        "87fbc62c64df8998566f919714fe3c8c2132737d56166b9c95dcf4e5ce98acd0",
    ),
    (
        "sig_2",
        concat!(
            "9a2a86ae7b26c080d2e1ed51c5b29bb29947423548503fba15cb25e261fa792d",
            "a5df9b8d10d19993a3d5c6f2a7055bb836101a40f7acca5c67bf590298143108",
        ),
    ),
    (
        "th_2",
        "da523df7c6b7a4dda138c3ac970db657faaa5c721c46acca6cd8f89f095a0a1a",
    ),
    (
        "frame_3_session_request",
        concat!(
            "0000005d8501020656a100a400816468323634018219078019043802f4030158",
            "40d364bf0d9390181088f3118379c2f10f45a4eae1d718792fa32d58decbb24c",
            "d4d624c5dea3283b343d06c2d55718c9af5dc4968ab20d41afac42398f59ae1f",
            "01",
        ),
    ),
    (
        "digest_3",
        "832201e56df8eef50c7d96bf2b5574d1cb32f3aa932f90d4b82dd58379fac3cb",
    ),
    (
        "sig_3",
        concat!(
            "d364bf0d9390181088f3118379c2f10f45a4eae1d718792fa32d58decbb24cd4",
            "d624c5dea3283b343d06c2d55718c9af5dc4968ab20d41afac42398f59ae1f01",
        ),
    ),
    (
        "th_3",
        "061d9ee332db832e7c3cd44061ff8ccd32dc4fe32aecb9db9c9a918fe89ea4f5",
    ),
    (
        "frame_4_session_accept",
        concat!(
            "000000ba850102075872a800a400816468323634018219078019043802f40301",
            "01582c302a300506032b6570032100705fbac01f5519899f437bc42e40255ae9",
            "ab54bff00de3433af7d687d9e71ad50200030004000558205555555555555555",
            "555555555555555555555555555555555555555555555555070008f45840b014",
            "e4385e8e1d29f061df4534b376fe387bfd21a4abc3a76b4431c74c2b397944f6",
            "a50c88776119257381646ea3c21e6c8972139a2d75f2a27d737ee05b710e",
        ),
    ),
    (
        "digest_4",
        "728405e008449e172d395bfc2133f7098a88a1d61032d3e851eabfec023b98d4",
    ),
    (
        "sig_4",
        concat!(
            "b014e4385e8e1d29f061df4534b376fe387bfd21a4abc3a76b4431c74c2b3979",
            "44f6a50c88776119257381646ea3c21e6c8972139a2d75f2a27d737ee05b710e",
        ),
    ),
    (
        "th_4",
        "cdf97099e56630861eb9ad965457f52a55f3347146036f7065c5eb1582bcf198",
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
        concat!(
            "000000a8850101015860a6000101582033333333333333333333333333333333",
            "33333333333333333333333333333333025820a09aa5f47a6759802ff955f8dc",
            "2d2a14a5c99d23be97f864127ff9383455a4f0036d676f6c64656e2d636c6965",
            "6e740481637561310600584042d7cda78c6f698bbf5a05efc6ffe70ea52bdcfc",
            "bfe0e4833f593c70c5872164bc462976c4b47316747def7db5af0a8621d2d89e",
            "16680feb0868acee49ddc204",
        ),
    ),
    (
        "digest_1",
        "960ddd5ea25c79e093ca5f3e3c02087a3698efe8d01921ff24409b12eb292a3e",
    ),
    (
        "sig_1",
        concat!(
            "42d7cda78c6f698bbf5a05efc6ffe70ea52bdcfcbfe0e4833f593c70c5872164",
            "bc462976c4b47316747def7db5af0a8621d2d89e16680feb0868acee49ddc204",
        ),
    ),
    (
        "th_1",
        "2787876076e98f3310e83d47ee51f97fc9e87ad5a5c5a01d110bb7c765921f75",
    ),
    (
        "frame_2_hello_ack",
        concat!(
            "0000007485010102582ca3000101582044444444444444444444444444444444",
            "444444444444444444444444444444440281637561315840c088df14d82c56ce",
            "3bb87b7b86a22b6b77bb68435985fb9025d6fea3952c0ac4f948c1e790bdd66a",
            "cd3d6ab57e3804d02a695b4cd235af6ee5773f9d2dc7b205",
        ),
    ),
    (
        "digest_2",
        "87fbc62c64df8998566f919714fe3c8c2132737d56166b9c95dcf4e5ce98acd0",
    ),
    (
        "sig_2",
        concat!(
            "c088df14d82c56ce3bb87b7b86a22b6b77bb68435985fb9025d6fea3952c0ac4",
            "f948c1e790bdd66acd3d6ab57e3804d02a695b4cd235af6ee5773f9d2dc7b205",
        ),
    ),
    (
        "th_2",
        "10003074c3f7123641e262760a4d180681c7b523c82864b7936ad9a46c112d38",
    ),
    ("frame_3_pair_request", "000000078501020341a0f6"),
    (
        "th_3",
        "8604d6b450520a47672097a318dbb6e55d8f722c96eb0da89268a7d3be108345",
    ),
    ("sas", "346 695"),
    (
        "frame_4_pair_accept",
        concat!(
            "00000038850102045831a2005820705fbac01f5519899f437bc42e40255ae9ab",
            "54bff00de3433af7d687d9e71ad5016b676f6c64656e2d686f7374f6",
        ),
    ),
    (
        "th_4",
        "5d1b5be7cf280525cbf191ee38b9babe97425238c6f82d466b9b999c903ca7b2",
    ),
    (
        "frame_5_session_request",
        concat!(
            "0000005d8501030656a100a400816468323634018219078019043802f4030158",
            "40121252a6f442839d47ca2f8464987d7e299e3c05b5a4e44f7ae700817ae9fe",
            "75a769649cae364c53761106f959d4e4a620e084d4ac82900b246507874df2a7",
            "01",
        ),
    ),
    (
        "digest_5",
        "2b916c1a2542ce973e5c714c7235fc1487e9e0c22c42acd1846da789e2ffc2ff",
    ),
    (
        "sig_5",
        concat!(
            "121252a6f442839d47ca2f8464987d7e299e3c05b5a4e44f7ae700817ae9fe75",
            "a769649cae364c53761106f959d4e4a620e084d4ac82900b246507874df2a701",
        ),
    ),
    (
        "th_5",
        "f93a2f68627c084bc74d309177b7f44b93c42ef821da4887184e2a1c16016da4",
    ),
    (
        "frame_6_session_accept",
        concat!(
            "000000ba850103075872a800a400816468323634018219078019043802f40301",
            "01582c302a300506032b6570032100705fbac01f5519899f437bc42e40255ae9",
            "ab54bff00de3433af7d687d9e71ad50200030004000558205555555555555555",
            "555555555555555555555555555555555555555555555555070008f45840d802",
            "8e6a60a247a0bbd327c577d5b253cfea085c951e689ffe04f3b4e0967d0e168b",
            "afd4c68353d66eb0e80242af45f009bcb60200df0f6413f3cf784483e609",
        ),
    ),
    (
        "digest_6",
        "e9d7bbdd0fd5bf991fff4d4a9be1d08f19b43b0c16cb2fef86ffd0b8717c2968",
    ),
    (
        "sig_6",
        concat!(
            "d8028e6a60a247a0bbd327c577d5b253cfea085c951e689ffe04f3b4e0967d0e",
            "168bafd4c68353d66eb0e80242af45f009bcb60200df0f6413f3cf784483e609",
        ),
    ),
    (
        "th_6",
        "90a4f894ca33c22793b1f2bd6b92ff29fa18c153b849abf5f0873fd6474a0556",
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
    record(
        &mut out,
        &["frame_2_hello_ack", "digest_2", "sig_2", "th_2"],
        &ack.wire[4..],
        chan.th(),
    );
    let mut i = 2;
    if !paired {
        let pair_request = chan.send(&PairRequest::default(), None).await.unwrap();
        record(
            &mut out,
            &["frame_3_pair_request", "", "", "th_3"],
            &pair_request,
            chan.th(),
        );
        out.push(("sas", Sas::derive(&chan.th()).render()));
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
