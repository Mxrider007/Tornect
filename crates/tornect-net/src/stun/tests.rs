use super::*;

use proptest::prelude::*;

use crate::udp::{is_probe, is_stun};

/// The transaction ID of the RFC 5769 §2.1–§2.3 vectors.
const RFC_TXID: StunTxid = [
    0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
];

/// The transaction ID of the RFC 5769 §2.4 vector.
const RFC_TXID_LONG_TERM: StunTxid = [
    0x78, 0xad, 0x34, 0x33, 0xc6, 0xad, 0x72, 0xc0, 0x29, 0xda, 0x41, 0x2e,
];

fn bytes(hex: &str) -> Vec<u8> {
    let digits: Vec<u8> = hex
        .bytes()
        .filter(u8::is_ascii_hexdigit)
        .map(|c| match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => c - b'A' + 10,
        })
        .collect();
    assert_eq!(digits.len() % 2, 0, "whole bytes");
    digits.chunks(2).map(|p| (p[0] << 4) | p[1]).collect()
}

/// RFC 5769 §2.1, "Sample Request" (108 bytes): SOFTWARE, PRIORITY,
/// ICE-CONTROLLED, USERNAME, MESSAGE-INTEGRITY, FINGERPRINT. Transcribed
/// from the RFC and checked by computation (docs/research/nat-traversal.md
/// §2.5: MESSAGE-INTEGRITY with the password `VOkJxbRl1RmTxUk/WvJxBt` and
/// the FINGERPRINT CRC both match).
fn rfc_request() -> Vec<u8> {
    bytes(
        "00 01 00 58 21 12 a4 42 b7 e7 a7 01 bc 34 d6 86 fa 87 df ae
         80 22 00 10 53 54 55 4e 20 74 65 73 74 20 63 6c 69 65 6e 74
         00 24 00 04 6e 00 01 ff
         80 29 00 08 93 2f f9 b1 51 26 3b 36
         00 06 00 09 65 76 74 6a 3a 68 36 76 59 20 20 20
         00 08 00 14 9a ea a7 0c bf d8 cb 56 78 1e f2 b5 b2 d3 f2 49 c1 b5 71 a2
         80 28 00 04 e5 7a 3b cf",
    )
}

/// RFC 5769 §2.2, "Sample IPv4 Response" (80 bytes) → `192.0.2.1:32853`.
fn rfc_response_v4() -> Vec<u8> {
    bytes(
        "01 01 00 3c 21 12 a4 42 b7 e7 a7 01 bc 34 d6 86 fa 87 df ae
         80 22 00 0b 74 65 73 74 20 76 65 63 74 6f 72 20
         00 20 00 08 00 01 a1 47 e1 12 a6 43
         00 08 00 14 2b 91 f5 99 fd 9e 90 c3 8c 74 89 f9 2a f9 ba 53 f0 6b e7 d7
         80 28 00 04 c0 7d 4c 96",
    )
}

/// RFC 5769 §2.3, "Sample IPv6 Response" (92 bytes) →
/// `[2001:db8:1234:5678:11:2233:4455:6677]:32853`.
fn rfc_response_v6() -> Vec<u8> {
    bytes(
        "01 01 00 48 21 12 a4 42 b7 e7 a7 01 bc 34 d6 86 fa 87 df ae
         80 22 00 0b 74 65 73 74 20 76 65 63 74 6f 72 20
         00 20 00 14 00 02 a1 47 01 13 a9 fa a5 d3 f1 79 bc 25 f4 b5 be d2 b9 d9
         00 08 00 14 a3 82 95 4e 4b e6 7b f1 17 84 c9 7c 82 92 c2 75 bf e3 ed 41
         80 28 00 04 c8 fb 0b 4c",
    )
}

/// RFC 5769 §2.4, "Sample Request with Long-Term Authentication" (116
/// bytes): USERNAME (the six katakana), NONCE, REALM `example.org`,
/// MESSAGE-INTEGRITY. Checked by computation like §2.1 (the long-term key
/// `MD5(username ":" realm ":" "TheMatrIX")`).
fn rfc_request_long_term() -> Vec<u8> {
    bytes(
        "00 01 00 60 21 12 a4 42 78 ad 34 33 c6 ad 72 c0 29 da 41 2e
         00 06 00 12 e3 83 9e e3 83 88 e3 83 aa e3 83 83 e3 82 af e3 82 b9 00 00
         00 15 00 1c 66 2f 2f 34 39 39 6b 39 35 34 64 36 4f 4c 33 34 6f 4c 39 46
                     53 54 76 79 36 34 73 41
         00 14 00 0b 65 78 61 6d 70 6c 65 2e 6f 72 67 00
         00 08 00 14 f6 70 24 65 6d d6 4a 3e 02 b8 e0 71 2e 85 c9 a2 8c a8 96 66",
    )
}

fn sa(text: &str) -> SocketAddr {
    text.parse().expect("a socket address")
}

/// A test-side message builder (Tornect itself never answers STUN): the
/// header with `kind` and `txid`, then each attribute padded to 4 bytes,
/// the length field covering them.
fn message(kind: u16, txid: &StunTxid, attrs: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&STUN_COOKIE);
    out.extend_from_slice(txid);
    for (ty, value) in attrs {
        out.extend_from_slice(&ty.to_be_bytes());
        out.extend_from_slice(&u16::try_from(value.len()).expect("short").to_be_bytes());
        out.extend_from_slice(value);
        out.resize(out.len().next_multiple_of(4), 0);
    }
    let length = u16::try_from(out.len() - HEADER_LEN).expect("short");
    out[2..4].copy_from_slice(&length.to_be_bytes());
    out
}

/// A (XOR-)MAPPED-ADDRESS value for `addr`.
fn address_value(addr: SocketAddr, xor: Option<&StunTxid>) -> Vec<u8> {
    let mut mask = [0_u8; 16];
    let mut port_mask = 0;
    if let Some(txid) = xor {
        mask[..4].copy_from_slice(&STUN_COOKIE);
        mask[4..].copy_from_slice(txid);
        port_mask = PORT_MASK;
    }
    let (family, ip): (u8, Vec<u8>) = match addr.ip() {
        IpAddr::V4(v4) => (FAMILY_V4, v4.octets().to_vec()),
        IpAddr::V6(v6) => (FAMILY_V6, v6.octets().to_vec()),
    };
    let mut value = vec![0, family];
    value.extend_from_slice(&(addr.port() ^ port_mask).to_be_bytes());
    value.extend(ip.iter().zip(mask).map(|(b, m)| b ^ m));
    value
}

fn xor_mapped(addr: SocketAddr, txid: &StunTxid) -> (u16, Vec<u8>) {
    (attr::XOR_MAPPED_ADDRESS, address_value(addr, Some(txid)))
}

fn mapped(addr: SocketAddr) -> (u16, Vec<u8>) {
    (attr::MAPPED_ADDRESS, address_value(addr, None))
}

fn software() -> (u16, Vec<u8>) {
    (0x8022, b"test vector ".to_vec())
}

/// The request is the bare 20-byte header (design §6.4): Binding request,
/// length 0, the cookie, the transaction ID. It is STUN-shaped for the
/// session socket's tee and never probe-shaped.
#[test]
fn the_request_is_the_bare_header() {
    let request = binding_request(&RFC_TXID);
    assert_eq!(
        request.to_vec(),
        bytes("00 01 00 00 21 12 a4 42 b7 e7 a7 01 bc 34 d6 86 fa 87 df ae")
    );
    assert_eq!(request.len(), STUN_REQUEST_LEN);
    assert!(is_stun(&request));
    assert!(!is_probe(&request));
    // A request is never read as a response, even its own.
    assert_eq!(parse_response(&request, &RFC_TXID), None);
}

/// RFC 5769 §2.2 and §2.3: both sample responses give the RFC's mapped
/// address, through their SOFTWARE, MESSAGE-INTEGRITY (skipped) and
/// FINGERPRINT (skipped, comprehension-optional).
#[test]
fn the_rfc_5769_responses_parse() {
    assert_eq!(rfc_response_v4().len(), 80);
    assert_eq!(rfc_response_v6().len(), 92);
    assert_eq!(
        parse_response(&rfc_response_v4(), &RFC_TXID),
        Some(StunReply::Mapped(sa("192.0.2.1:32853")))
    );
    assert_eq!(
        parse_response(&rfc_response_v6(), &RFC_TXID),
        Some(StunReply::Mapped(sa(
            "[2001:db8:1234:5678:11:2233:4455:6677]:32853"
        )))
    );
    // Another request's transaction ID: not ours.
    assert_eq!(
        parse_response(&rfc_response_v4(), &RFC_TXID_LONG_TERM),
        None
    );
}

/// RFC 5769 §2.1 and §2.4 are Binding requests: refused on the class,
/// whatever their attributes.
#[test]
fn the_rfc_5769_requests_are_refused() {
    let short_term = rfc_request();
    let long_term = rfc_request_long_term();
    assert_eq!((short_term.len(), long_term.len()), (108, 116));
    assert!(is_stun(&short_term) && is_stun(&long_term));
    assert_eq!(parse_response(&short_term, &RFC_TXID), None);
    assert_eq!(parse_response(&long_term, &RFC_TXID_LONG_TERM), None);
    // The same messages as indications (class 0b01) are refused too.
    for (mut message, txid) in [(short_term, RFC_TXID), (long_term, RFC_TXID_LONG_TERM)] {
        message[1] = 0x11;
        assert_eq!(parse_response(&message, &txid), None);
    }
}

/// The header checks of design §6.4, each on an otherwise good response.
#[test]
fn the_header_must_be_a_binding_response_to_our_transaction() {
    let good = message(
        BINDING_SUCCESS,
        &RFC_TXID,
        &[xor_mapped(sa("198.51.100.7:40000"), &RFC_TXID)],
    );
    let want = Some(StunReply::Mapped(sa("198.51.100.7:40000")));
    assert_eq!(parse_response(&good, &RFC_TXID), want);

    // Shorter than a header, or longer than 548 bytes.
    for len in [0, 1, 19] {
        assert_eq!(
            parse_response(&good[..len.min(good.len())], &RFC_TXID),
            None
        );
    }
    // The cookie, each byte of the transaction ID.
    for at in 4..20 {
        let mut bad = good.clone();
        bad[at] ^= 0x01;
        assert_eq!(parse_response(&bad, &RFC_TXID), None, "byte {at}");
    }
    // Byte 0 above 0x03 (the first two bits, or the RFC 9443 STUN range).
    for lead in [0x04, 0x40, 0x81, 0xc1] {
        let mut bad = good.clone();
        bad[0] = lead;
        assert_eq!(parse_response(&bad, &RFC_TXID), None, "lead {lead:#x}");
    }
    // Other methods and classes.
    for kind in [0x0001_u16, 0x0011, 0x0102, 0x0103, 0x0201, 0x0000, 0x3eef] {
        let mut bad = good.clone();
        bad[..2].copy_from_slice(&kind.to_be_bytes());
        assert_eq!(parse_response(&bad, &RFC_TXID), None, "type {kind:#06x}");
    }
    // A length field that does not match the datagram.
    for length in [0_u16, 8, 16, 20, 0xffff] {
        let mut bad = good.clone();
        bad[2..4].copy_from_slice(&length.to_be_bytes());
        assert_eq!(parse_response(&bad, &RFC_TXID), None, "length {length}");
    }
    // A length that matches but is not a multiple of 4.
    let mut odd = good.clone();
    odd.extend_from_slice(&[0, 0]);
    let length = u16::try_from(odd.len() - HEADER_LEN).unwrap();
    odd[2..4].copy_from_slice(&length.to_be_bytes());
    assert_eq!(parse_response(&odd, &RFC_TXID), None);
}

/// 548 bytes is the largest response taken; one more word is refused.
#[test]
fn the_size_cap_is_548_bytes() {
    let padding = |n: usize| (0x8022, vec![b'x'; n]);
    let at_cap = message(
        BINDING_SUCCESS,
        &RFC_TXID,
        &[
            xor_mapped(sa("198.51.100.7:40000"), &RFC_TXID),
            padding(512),
        ],
    );
    assert_eq!(at_cap.len(), STUN_MAX_LEN);
    assert_eq!(
        parse_response(&at_cap, &RFC_TXID),
        Some(StunReply::Mapped(sa("198.51.100.7:40000")))
    );
    let over = message(
        BINDING_SUCCESS,
        &RFC_TXID,
        &[
            xor_mapped(sa("198.51.100.7:40000"), &RFC_TXID),
            padding(516),
        ],
    );
    assert_eq!(over.len(), STUN_MAX_LEN + 4);
    assert_eq!(parse_response(&over, &RFC_TXID), None);
}

/// An error response is `ErrorResponse`, with or without ERROR-CODE and
/// whatever unknown attributes it carries (RFC 8489 §6.3.4); a malformed
/// one is still refused.
#[test]
fn an_error_response_is_read_as_such() {
    let error_code = (0x0009, vec![0, 0, 4, 20, b'S', b't', b'a', b'l', b'e']);
    for attrs in [
        vec![],
        vec![error_code.clone()],
        vec![error_code.clone(), (0x7777, vec![1, 2, 3, 4]), software()],
        vec![xor_mapped(sa("198.51.100.7:40000"), &RFC_TXID)],
    ] {
        assert_eq!(
            parse_response(&message(BINDING_ERROR, &RFC_TXID, &attrs), &RFC_TXID),
            Some(StunReply::ErrorResponse)
        );
    }
    let mut overrun = message(BINDING_ERROR, &RFC_TXID, &[error_code]);
    overrun[22..24].copy_from_slice(&0x0100_u16.to_be_bytes());
    assert_eq!(parse_response(&overrun, &RFC_TXID), None);
}

/// RFC 8489 §6.3.3: an unknown comprehension-required attribute discards a
/// success response; an unknown comprehension-optional one is skipped, and
/// so are the six required ones that carry nothing for us.
#[test]
fn unknown_required_attributes_discard_a_success() {
    let address = xor_mapped(sa("198.51.100.7:40000"), &RFC_TXID);
    let want = Some(StunReply::Mapped(sa("198.51.100.7:40000")));
    for unknown in [0x0000_u16, 0x0002, 0x0003, 0x0007, 0x0024, 0x7fff] {
        for attrs in [
            vec![address.clone(), (unknown, vec![0; 4])],
            vec![(unknown, vec![]), address.clone()],
        ] {
            assert_eq!(
                parse_response(&message(BINDING_SUCCESS, &RFC_TXID, &attrs), &RFC_TXID),
                None,
                "type {unknown:#06x}"
            );
        }
    }
    for skipped in attr::SKIPPED_REQUIRED
        .into_iter()
        .chain([0x8000, 0x8022, 0x8028, 0x802b, 0x802c, 0xffff])
    {
        let attrs = [(skipped, vec![0xab; 5]), address.clone(), (skipped, vec![])];
        assert_eq!(
            parse_response(&message(BINDING_SUCCESS, &RFC_TXID, &attrs), &RFC_TXID),
            want,
            "type {skipped:#06x}"
        );
    }
}

/// An attribute whose value, or whose padding, runs past the message
/// discards it.
#[test]
fn an_overrunning_attribute_discards_the_response() {
    let good = message(
        BINDING_SUCCESS,
        &RFC_TXID,
        &[xor_mapped(sa("198.51.100.7:40000"), &RFC_TXID), software()],
    );
    assert!(parse_response(&good, &RFC_TXID).is_some());
    // SOFTWARE's length is at 34..36 (after the 12-byte XOR-MAPPED-ADDRESS);
    // its 12 bytes end the message. 13 to 16 still pad to 16 and overrun.
    for len in [13_u16, 16, 17, 0xffff] {
        let mut bad = good.clone();
        bad[34..36].copy_from_slice(&len.to_be_bytes());
        assert_eq!(parse_response(&bad, &RFC_TXID), None, "length {len}");
    }
    // A shorter length leaves SOFTWARE's last word to be read as a further
    // attribute header (`74 6f 72 20`: type 0x746f, length 0x7220), which
    // overruns.
    let mut short = good.clone();
    short[34..36].copy_from_slice(&8_u16.to_be_bytes());
    assert_eq!(parse_response(&short, &RFC_TXID), None);
}

/// The address attributes: the family must match the value's length, the
/// reserved byte is ignored, a malformed one discards the response.
#[test]
fn address_attributes_are_checked() {
    let v4 = sa("198.51.100.7:40000");
    let v6 = sa("[2001:db8::7]:40000");
    for addr in [v4, v6] {
        let mut value = address_value(addr, Some(&RFC_TXID));
        value[0] = 0xff;
        let reply = parse_response(
            &message(
                BINDING_SUCCESS,
                &RFC_TXID,
                &[(attr::XOR_MAPPED_ADDRESS, value)],
            ),
            &RFC_TXID,
        );
        assert_eq!(reply, Some(StunReply::Mapped(addr)));
    }
    let malformed = [
        vec![0, FAMILY_V4, 0, 1, 1, 2, 3],
        vec![0, FAMILY_V4, 0, 1, 1, 2, 3, 4, 5],
        [vec![0, FAMILY_V4, 0, 1], vec![0; 16]].concat(),
        [vec![0, FAMILY_V6, 0, 1], vec![0; 4]].concat(),
        [vec![0, FAMILY_V6, 0, 1], vec![0; 15]].concat(),
        vec![0, 0x03, 0, 1, 1, 2, 3, 4],
        vec![0, 0x00, 0, 1, 1, 2, 3, 4],
        vec![0],
        vec![],
    ];
    for kind in [attr::XOR_MAPPED_ADDRESS, attr::MAPPED_ADDRESS] {
        for value in &malformed {
            for attrs in [
                vec![(kind, value.clone())],
                vec![xor_mapped(v4, &RFC_TXID), (kind, value.clone())],
            ] {
                assert_eq!(
                    parse_response(&message(BINDING_SUCCESS, &RFC_TXID, &attrs), &RFC_TXID),
                    None,
                    "type {kind:#06x} value {value:?}"
                );
            }
        }
    }
}

/// The first XOR-MAPPED-ADDRESS wins; MAPPED-ADDRESS is read only when
/// there is none; a success response with neither is refused.
#[test]
fn the_first_xor_mapped_address_wins() {
    let a = sa("198.51.100.7:40000");
    let b = sa("203.0.113.9:50000");
    let read = |attrs: &[(u16, Vec<u8>)]| {
        parse_response(&message(BINDING_SUCCESS, &RFC_TXID, attrs), &RFC_TXID)
    };
    assert_eq!(
        read(&[xor_mapped(a, &RFC_TXID), xor_mapped(b, &RFC_TXID)]),
        Some(StunReply::Mapped(a))
    );
    assert_eq!(
        read(&[mapped(b), xor_mapped(a, &RFC_TXID)]),
        Some(StunReply::Mapped(a))
    );
    assert_eq!(
        read(&[xor_mapped(a, &RFC_TXID), mapped(b)]),
        Some(StunReply::Mapped(a))
    );
    assert_eq!(read(&[mapped(b), mapped(a)]), Some(StunReply::Mapped(b)));
    assert_eq!(read(&[software()]), None);
    assert_eq!(read(&[]), None);
    // The XOR decoding: an IPv6 address read without its XOR is another
    // address, and an XOR-MAPPED-ADDRESS read under another transaction ID
    // is too.
    let v6 = sa("[2001:db8:1234:5678:11:2233:4455:6677]:32853");
    let mut other = RFC_TXID;
    other[11] ^= 0xff;
    let foreign = message(BINDING_SUCCESS, &RFC_TXID, &[xor_mapped(v6, &other)]);
    assert_ne!(
        parse_response(&foreign, &RFC_TXID),
        Some(StunReply::Mapped(v6))
    );
}

/// Decision M1-83: a reply's `Debug` names the family and class of the
/// mapped address, never its digits.
#[test]
fn no_debug_prints_the_mapped_address() {
    for addr in [sa("198.51.100.73:40123"), sa("[2001:db8::7a]:40123")] {
        let text = format!(
            "{:?} {:#?}",
            StunReply::Mapped(addr),
            StunReply::Mapped(addr)
        );
        for needle in ["198", "51", "100", "73", "40123", "2001", "db8", "7a"] {
            assert!(!text.contains(needle), "{needle} in {text}");
        }
        assert!(text.contains("v4") || text.contains("v6"), "{text}");
    }
    assert_eq!(format!("{:?}", StunReply::ErrorResponse), "ErrorResponse");
}

/// Corpus policy (decision M1-36): the `stun` fuzz target's seeds are the
/// RFC 5769 vectors above, read with the §2.1–§2.3 transaction ID the
/// target fixes, plus one error response.
#[test]
fn the_fuzz_seeds_are_the_rfc_vectors() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fuzz/seeds/stun");
    let read = |name: &str| std::fs::read(format!("{dir}/{name}")).expect("a committed seed");
    assert_eq!(read("rfc5769-ipv4-response.bin"), rfc_response_v4());
    assert_eq!(read("rfc5769-ipv6-response.bin"), rfc_response_v6());
    assert_eq!(read("rfc5769-request.bin"), rfc_request());
    assert_eq!(
        read("rfc5769-long-term-request.bin"),
        rfc_request_long_term()
    );
    let error = read("error-response.bin");
    assert_eq!(
        error,
        message(
            BINDING_ERROR,
            &RFC_TXID,
            &[
                (0x0009, vec![0, 0, 4, 20, b'S', b't', b'a', b'l', b'e']),
                software()
            ]
        )
    );
    assert_eq!(
        parse_response(&error, &RFC_TXID),
        Some(StunReply::ErrorResponse)
    );
}

fn strings(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}

/// Design §5.3: hosts are grouped by the operator table first, by their
/// last two labels otherwise; case, a final dot, brackets and the port do
/// not matter, and an IP literal is its own operator.
#[test]
fn entries_are_grouped_by_operator() {
    for (entry, key) in [
        ("stun.l.google.com:19302", "google.com"),
        ("stun1.l.google.com:19302", "google.com"),
        ("STUN.L.Google.COM.:19302", "google.com"),
        ("google.com:3478", "google.com"),
        ("stun.cloudflare.com:3478", "cloudflare.com"),
        ("global.stun.twilio.com:3478", "twilio.com"),
        ("stun.nextcloud.com:443", "nextcloud.com"),
        ("notgoogle.com:3478", "notgoogle.com"),
        ("stun.example.org:3478", "example.org"),
        ("a.b.stun.example.org:3478", "example.org"),
        ("stun.example.co.uk:3478", "co.uk"),
        ("localhost:3478", "localhost"),
        ("192.0.2.7:3478", "192.0.2.7"),
        ("[2001:DB8::7]:3478", "2001:db8::7"),
    ] {
        assert_eq!(operator(entry), key, "{entry}");
    }
    let names: Vec<&str> = STUN_OPERATORS.iter().map(|(_, name)| *name).collect();
    assert_eq!(
        names,
        [
            "Cloudflare, Inc.",
            "Google LLC",
            "Twilio Inc.",
            "Nextcloud GmbH"
        ]
    );
}

/// Design §5.4: the default list gives the viewer Cloudflare and Twilio and
/// the host Google and Nextcloud, each entry on a port the STUN filter
/// admits.
#[test]
fn the_default_list_splits_into_two_operators_per_side() {
    let list = tornect_core::config::Network::default().stun_servers;
    assert_eq!(
        partition(&list, TornectRole::Viewer),
        strings(&["stun.cloudflare.com:3478", "global.stun.twilio.com:3478"])
    );
    assert_eq!(
        partition(&list, TornectRole::Host),
        strings(&["stun.l.google.com:19302", "stun.nextcloud.com:443"])
    );
    for entry in &list {
        let port: u16 = entry.rsplit_once(':').unwrap().1.parse().unwrap();
        assert_ne!(port, 0, "{entry}");
    }
}

/// Design §5.3: the earlier default (Google twice, then Cloudflare) puts
/// Google in one part only, however the entries are ordered; a list of one
/// operator is both sides' part; an empty list is nobody's.
#[test]
fn no_operator_is_in_both_parts() {
    let old = strings(&tornect_core::config::OLD_DEFAULT_STUN);
    assert_eq!(
        partition(&old, TornectRole::Viewer),
        strings(&["stun.l.google.com:19302", "stun1.l.google.com:19302"])
    );
    assert_eq!(
        partition(&old, TornectRole::Host),
        strings(&["stun.cloudflare.com:3478"])
    );
    let mixed = strings(&[
        "stun.l.google.com:19302",
        "stun.cloudflare.com:3478",
        "stun1.l.google.com:19302",
    ]);
    assert_eq!(
        partition(&mixed, TornectRole::Viewer),
        strings(&["stun.l.google.com:19302", "stun1.l.google.com:19302"])
    );
    assert_eq!(
        partition(&mixed, TornectRole::Host),
        strings(&["stun.cloudflare.com:3478"])
    );

    let one = strings(&["stun.l.google.com:19302", "stun2.l.google.com:19302"]);
    assert_eq!(partition(&one, TornectRole::Viewer), one);
    assert_eq!(partition(&one, TornectRole::Host), one);
    let twice = strings(&["stun.example.org:3478", "stun.example.org:3478"]);
    assert_eq!(
        partition(&twice, TornectRole::Host),
        strings(&["stun.example.org:3478"])
    );

    assert!(partition(&[], TornectRole::Viewer).is_empty());
    assert!(partition(&[], TornectRole::Host).is_empty());
    let three = strings(&["a.one.org:1", "b.two.org:2", "c.three.org:3"]);
    assert_eq!(
        partition(&three, TornectRole::Viewer),
        strings(&["a.one.org:1", "c.three.org:3"])
    );
    assert_eq!(
        partition(&three, TornectRole::Host),
        strings(&["b.two.org:2"])
    );
}

/// The residual of design §5.3's split (the review of steps B2 and B3):
/// each computer splits its own list, so the parts are disjoint only when
/// both computers use the same list. A viewer whose list has one entry
/// put before the default shifts every operator's place, and shares Google
/// and Nextcloud with a host on the default list: the config, module and
/// partition docs state the condition.
#[test]
fn only_the_same_list_on_both_computers_keeps_the_parts_apart() {
    let default = tornect_core::config::Network::default().stun_servers;
    let mut edited = strings(&["stun.example.org:3478"]);
    edited.extend(default.iter().cloned());
    let viewer = partition(&edited, TornectRole::Viewer);
    assert_eq!(
        viewer,
        strings(&[
            "stun.example.org:3478",
            "stun.l.google.com:19302",
            "stun.nextcloud.com:443",
        ])
    );
    let host = partition(&default, TornectRole::Host);
    let shared: Vec<&String> = viewer.iter().filter(|v| host.contains(v)).collect();
    assert_eq!(
        shared,
        ["stun.l.google.com:19302", "stun.nextcloud.com:443"],
        "an operator in both computers' parts"
    );
    let host = partition(&edited, TornectRole::Host);
    assert!(
        !viewer
            .iter()
            .any(|v| host.iter().any(|h| operator(h) == operator(v))),
        "the same list on both sides: {viewer:?} {host:?}"
    );
}

fn any_addr() -> impl Strategy<Value = SocketAddr> {
    prop_oneof![
        (any::<[u8; 4]>(), any::<u16>())
            .prop_map(|(ip, port)| SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port)),
        (any::<[u8; 16]>(), any::<u16>())
            .prop_map(|(ip, port)| SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port)),
    ]
}

/// Comprehension-optional attributes of any length, skipped by the reader.
fn optional_attrs() -> impl Strategy<Value = Vec<(u16, Vec<u8>)>> {
    proptest::collection::vec(
        (
            0x8000_u16..=0xffff,
            proptest::collection::vec(any::<u8>(), 0..40),
        ),
        0..4,
    )
}

/// A list of entries from a small set of operators, in any order, with
/// repeats.
fn any_list() -> impl Strategy<Value = Vec<String>> {
    proptest::collection::vec(
        (
            prop::sample::select(vec!["stun", "stun1", "a.b", "STUN"]),
            prop::sample::select(vec![
                "google.com",
                "cloudflare.com",
                "example.org",
                "example.net",
                "twilio.com",
            ]),
            1_u16..,
        )
            .prop_map(|(sub, domain, port)| format!("{sub}.{domain}:{port}")),
        0..10,
    )
}

proptest! {
    /// Design §5.3 for any list: with two operators or more, no operator is
    /// in both parts and the parts together hold every entry once; with one,
    /// both parts are the whole list.
    #[test]
    fn the_partition_never_shares_an_operator(list in any_list()) {
        let viewer = partition(&list, TornectRole::Viewer);
        let host = partition(&list, TornectRole::Host);
        let mut operators: Vec<String> = list.iter().map(|e| operator(e)).collect();
        operators.sort();
        operators.dedup();
        let mut unique = list.clone();
        unique.sort();
        unique.dedup();
        if operators.len() == 1 {
            prop_assert_eq!(&viewer, &host);
            let mut whole = viewer.clone();
            whole.sort();
            prop_assert_eq!(whole, unique);
        } else {
            for v in &viewer {
                prop_assert!(!host.iter().any(|h| operator(h) == operator(v)), "{} {:?}", v, host);
            }
            let mut both: Vec<String> = viewer.iter().chain(&host).cloned().collect();
            both.sort();
            prop_assert_eq!(both, unique);
        }
        if !list.is_empty() {
            prop_assert!(!viewer.is_empty());
            prop_assert_eq!(operator(&viewer[0]), operator(&list[0]));
        }
    }

    /// A response built from any address, transaction ID and optional
    /// attributes reads back as that address, XOR-mapped or plain.
    #[test]
    fn any_mapped_address_round_trips(
        addr in any_addr(),
        txid in any::<StunTxid>(),
        before in optional_attrs(),
        after in optional_attrs(),
        plain in any::<bool>(),
    ) {
        let address = if plain { mapped(addr) } else { xor_mapped(addr, &txid) };
        let attrs: Vec<_> = before.into_iter().chain([address]).chain(after).collect();
        let response = message(BINDING_SUCCESS, &txid, &attrs);
        prop_assume!(response.len() <= STUN_MAX_LEN);
        prop_assert!(is_stun(&response));
        prop_assert_eq!(parse_response(&response, &txid), Some(StunReply::Mapped(addr)));
        let mut other = txid;
        other[0] ^= 1;
        prop_assert_eq!(parse_response(&response, &other), None);
    }

    /// Arbitrary bytes never panic the reader, and whatever it accepts has
    /// the shape design §6.4 asks for.
    #[test]
    fn random_bytes_never_panic(data in proptest::collection::vec(any::<u8>(), 0..700)) {
        let mut txid = RFC_TXID;
        if data.len() >= HEADER_LEN {
            txid.copy_from_slice(&data[8..20]);
        }
        if let Some(reply) = parse_response(&data, &txid) {
            prop_assert!((HEADER_LEN..=STUN_MAX_LEN).contains(&data.len()));
            prop_assert_eq!(&data[4..8], &STUN_COOKIE[..]);
            let kind = u16::from_be_bytes([data[0], data[1]]);
            match reply {
                StunReply::Mapped(_) => prop_assert_eq!(kind, BINDING_SUCCESS),
                StunReply::ErrorResponse => prop_assert_eq!(kind, BINDING_ERROR),
            }
        }
    }

    /// A good header in front of arbitrary attribute bytes reaches the
    /// attribute walk; it never panics either.
    #[test]
    fn random_attributes_never_panic(
        tail in proptest::collection::vec(any::<u8>(), 0..132),
        error in any::<bool>(),
    ) {
        let mut tail = tail;
        tail.truncate(tail.len() / 4 * 4);
        let kind = if error { BINDING_ERROR } else { BINDING_SUCCESS };
        let mut response = message(kind, &RFC_TXID, &[]);
        response.extend_from_slice(&tail);
        let length = u16::try_from(tail.len()).unwrap();
        response[2..4].copy_from_slice(&length.to_be_bytes());
        let reply = parse_response(&response, &RFC_TXID);
        if error {
            prop_assert!(matches!(reply, None | Some(StunReply::ErrorResponse)));
        } else {
            prop_assert!(matches!(reply, None | Some(StunReply::Mapped(_))));
        }
    }
}
