use super::*;

use proptest::prelude::*;

use crate::udp::{is_probe, is_stun};

const TOKEN: [u8; 32] = [0x11; 32];
const TXID_1_12: Txid = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

fn noise() -> [u8; NOISE_LEN] {
    let mut noise = [0; NOISE_LEN];
    noise[0] = 200;
    noise[1] = 0xff;
    for (i, b) in noise[2..].iter_mut().enumerate() {
        *b = 0xa0 + u8::try_from(i).expect("ten bytes");
    }
    noise
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Known answers computed apart from this code (Python's `hmac` and
/// `hashlib`: HKDF-SHA256 of RFC 5869 with an empty salt, then
/// HMAC-SHA256 truncated to 16 bytes), for token `11 × 32`, txid `01..0c`,
/// lead noise 200 (lead `0x04 + 200 % 60 = 0x18`), flag noise `0xff` and
/// padding `a0..a9`.
#[test]
fn the_probe_layout_and_key_match_known_answers() {
    let key = ProbeKey::derive(&TOKEN);
    assert_eq!(
        hex(&key.0),
        "aadb6e359543606e1dec7343efb949f16ce3c9b112df0ad9c26005b9468e00c5"
    );
    let request = key.seal(false, TornectRole::Viewer, &TXID_1_12, &noise());
    assert_eq!(
        hex(&request),
        "180102030405060708090a0b0cfca0a1a2a3a4a5a6a7a8a934a09a016f0deabc1a273a6794793881"
    );
    let response = key.seal(true, TornectRole::Host, &TXID_1_12, &noise());
    assert_eq!(
        hex(&response),
        "180102030405060708090a0b0cffa0a1a2a3a4a5a6a7a8a96cc0e2fd468ee2c51ca2889f7f6dac0b"
    );
}

/// Corpus policy (decision M1-36): the `probe` fuzz target's datagram
/// seeds are the known answers above, so the target's fixed key reads them.
#[test]
fn the_fuzz_seeds_are_the_known_answers() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fuzz/seeds/probe");
    let read = |name: &str| std::fs::read(format!("{dir}/{name}")).expect("a committed seed");
    let key = ProbeKey::derive(&TOKEN);
    let request = key.seal(false, TornectRole::Viewer, &TXID_1_12, &noise());
    let response = key.seal(true, TornectRole::Host, &TXID_1_12, &noise());
    assert_eq!(read("request.bin"), request);
    assert_eq!(read("response.bin"), response);
    assert!(key.decode(TornectRole::Host, &read("request.bin")).is_ok());
    assert!(
        key.decode(TornectRole::Viewer, &read("response.bin"))
            .is_ok()
    );
}

/// A request and its response decode on the other side with the sender,
/// the kind and the txid they were sealed with, and have the same size.
#[test]
fn requests_and_responses_round_trip_both_ways() {
    let key = ProbeKey::derive(&TOKEN);
    for (sender, receiver) in [
        (TornectRole::Viewer, TornectRole::Host),
        (TornectRole::Host, TornectRole::Viewer),
    ] {
        let (txid, request) = key.request(sender).expect("OS randomness");
        let read = key.decode(receiver, &request).expect("a valid request");
        assert_eq!(
            read,
            Probe {
                response: false,
                sender,
                txid
            }
        );
        let response = key.response(receiver, &txid).expect("OS randomness");
        assert_eq!(request.len(), response.len());
        let read = key.decode(sender, &response).expect("a valid response");
        assert_eq!(
            read,
            Probe {
                response: true,
                sender: receiver,
                txid
            }
        );
    }
}

/// A probe sealed under another session's key is refused on its tag.
#[test]
fn a_probe_of_another_session_is_refused() {
    let key = ProbeKey::derive(&TOKEN);
    let other = ProbeKey::derive(&[0x12; 32]);
    let (_, request) = other.request(TornectRole::Host).expect("OS randomness");
    assert_eq!(
        key.decode(TornectRole::Viewer, &request),
        Err(ProbeDrop::Tag)
    );
    let response = other
        .response(TornectRole::Viewer, &TXID_1_12)
        .expect("OS randomness");
    assert_eq!(
        key.decode(TornectRole::Host, &response),
        Err(ProbeDrop::Tag)
    );
}

/// The key is a subkey of the token under its own label: the token itself,
/// used as the key, does not verify a probe.
#[test]
fn the_token_itself_is_not_the_key() {
    let key = ProbeKey::derive(&TOKEN);
    let raw = ProbeKey(TOKEN);
    let request = raw.seal(false, TornectRole::Viewer, &TXID_1_12, &noise());
    assert_eq!(key.decode(TornectRole::Host, &request), Err(ProbeDrop::Tag));
}

/// A lead byte outside `0x04..=0x3F` and any other length are refused on
/// shape, before the tag is computed.
#[test]
fn a_lead_outside_the_range_or_another_length_is_refused() {
    let key = ProbeKey::derive(&TOKEN);
    let request = key.seal(false, TornectRole::Viewer, &TXID_1_12, &noise());
    for lead in (0..=0x03).chain(0x40..=0xff) {
        let mut bad = request;
        bad[0] = lead;
        assert_eq!(
            key.decode(TornectRole::Host, &bad),
            Err(ProbeDrop::Shape),
            "{lead:#04x}"
        );
    }
    assert_eq!(
        key.decode(TornectRole::Host, &request[..39]),
        Err(ProbeDrop::Shape)
    );
    let mut long = request.to_vec();
    long.push(0);
    assert_eq!(key.decode(TornectRole::Host, &long), Err(ProbeDrop::Shape));
    assert_eq!(key.decode(TornectRole::Host, &[]), Err(ProbeDrop::Shape));
}

/// A side never accepts a probe that claims its own role, whatever its
/// kind: one of its own probes reflected back to it is dropped.
#[test]
fn a_probe_from_the_receivers_own_role_is_refused() {
    let key = ProbeKey::derive(&TOKEN);
    for role in [TornectRole::Viewer, TornectRole::Host] {
        let (txid, request) = key.request(role).expect("OS randomness");
        assert_eq!(key.decode(role, &request), Err(ProbeDrop::OwnRole));
        let response = key.response(role, &txid).expect("OS randomness");
        assert_eq!(key.decode(role, &response), Err(ProbeDrop::OwnRole));
    }
}

/// `decode` holds no state: the same datagram reads the same twice. Each
/// request is answered once by the checklist, which remembers the txids it
/// answered (`checklist::tests`).
#[test]
fn decoding_is_stateless_and_replays_are_the_checklists() {
    let key = ProbeKey::derive(&TOKEN);
    let (_, request) = key.request(TornectRole::Viewer).expect("OS randomness");
    assert_eq!(
        key.decode(TornectRole::Host, &request),
        key.decode(TornectRole::Host, &request)
    );
}

/// Every lead noise value gives a lead inside the range, every value of the
/// range is reachable, and the session socket's tee takes every probe as a
/// probe: never STUN, never QUIC (bit `0x40` clear).
#[test]
fn every_lead_is_a_probe_lead_and_never_stun_or_quic() {
    let key = ProbeKey::derive(&TOKEN);
    let mut seen = [false; 256];
    for r in 0..=255u8 {
        let mut noise = noise();
        noise[0] = r;
        let probe = key.seal(r % 2 == 0, TornectRole::Host, &TXID_1_12, &noise);
        assert!(PROBE_LEADS.contains(&probe[0]));
        assert!(is_probe(&probe));
        assert!(!is_stun(&probe));
        assert_eq!(probe[0] & 0x40, 0);
        seen[usize::from(probe[0])] = true;
    }
    assert!(PROBE_LEADS.clone().all(|lead| seen[usize::from(lead)]));
}

/// Across 1000 requests of one sender, every bit varies except the two
/// meaningful flag bits (byte 13, bits 0 and 1) and the two high bits of
/// the lead (the lead range): the probe carries no constant magic or
/// version (design §6.2).
#[test]
fn no_bit_is_constant_across_requests_but_the_flags_and_the_lead_range() {
    let key = ProbeKey::derive(&TOKEN);
    let first = key.request(TornectRole::Viewer).expect("OS randomness").1;
    let mut varies = [0u8; PROBE_LEN];
    for _ in 0..1000 {
        let (_, request) = key.request(TornectRole::Viewer).expect("OS randomness");
        for (v, (a, b)) in varies.iter_mut().zip(first.iter().zip(&request)) {
            *v |= a ^ b;
        }
    }
    let mut expected = [0xff; PROBE_LEN];
    expected[0] = 0x3f;
    expected[FLAGS] = 0xfc;
    assert_eq!(varies, expected);
    assert_eq!(first[FLAGS] & FLAG_BITS, 0);
}

/// The fixed flag bits of each kind and sender.
#[test]
fn the_flag_bits_name_the_kind_and_the_sender() {
    let key = ProbeKey::derive(&TOKEN);
    let mut quiet = noise();
    quiet[1] = 0;
    for (response, sender, bits) in [
        (false, TornectRole::Viewer, 0b00),
        (true, TornectRole::Viewer, 0b01),
        (false, TornectRole::Host, 0b10),
        (true, TornectRole::Host, 0b11),
    ] {
        let probe = key.seal(response, sender, &TXID_1_12, &quiet);
        assert_eq!(probe[FLAGS], bits);
    }
}

/// Nothing prints the key or a txid.
#[test]
fn no_debug_prints_the_key_or_a_txid() {
    let key = ProbeKey::derive(&TOKEN);
    let text = format!("{key:?}");
    assert_eq!(text, "ProbeKey(..)");
    let (_, request) = key.request(TornectRole::Viewer).expect("OS randomness");
    let probe = key.decode(TornectRole::Host, &request).expect("valid");
    assert_eq!(
        format!("{probe:?}"),
        "Probe { response: false, sender: Viewer, .. }"
    );
}

proptest! {
    /// Flipping any one bit of a sealed probe makes it refused: the tag
    /// covers every byte, and the lead and the length are checked first.
    #[test]
    fn any_flipped_bit_is_refused(
        txid in any::<Txid>(),
        noise in any::<[u8; NOISE_LEN]>(),
        response in any::<bool>(),
        host in any::<bool>(),
        bit in 0..PROBE_LEN * 8,
    ) {
        let key = ProbeKey::derive(&TOKEN);
        let sender = if host { TornectRole::Host } else { TornectRole::Viewer };
        let receiver = if host { TornectRole::Viewer } else { TornectRole::Host };
        let mut probe = key.seal(response, sender, &txid, &noise);
        prop_assert_eq!(
            key.decode(receiver, &probe),
            Ok(Probe { response, sender, txid })
        );
        probe[bit / 8] ^= 1 << (bit % 8);
        let read = key.decode(receiver, &probe);
        prop_assert!(matches!(read, Err(ProbeDrop::Shape | ProbeDrop::Tag)), "{:?}", read);
    }

    /// Arbitrary bytes never panic the decoder, and none of them decodes
    /// unless it carries a tag made with the key.
    #[test]
    fn random_bytes_never_decode(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
        let key = ProbeKey::derive(&TOKEN);
        let read = key.decode(TornectRole::Host, &bytes);
        prop_assert!(read.is_err());
    }
}
