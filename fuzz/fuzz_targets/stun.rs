//! The STUN Binding codec (design `direct` §6.4 and §8.7, decisions M1-81
//! and M1-86) fed arbitrary bytes: `parse_response` never panics, and
//! whatever it accepts
//!
//! - has the §6.4 shape: 20 to 548 bytes, the magic cookie, the transaction
//!   ID it was asked for, a length field equal to the rest of the datagram
//!   and a multiple of 4, and the Binding success type for a mapped address
//!   or the error type for an error response;
//! - is refused under any other transaction ID, and once any byte of the
//!   cookie or the transaction ID is flipped;
//! - is the same whether read with the RFC 5769 transaction ID the seeds
//!   carry or with the input's own (bytes 8..20), so the fuzzer reaches the
//!   attribute walk of inputs it made up;
//! - prints no address through `Debug` (decision M1-83).
//!
//! ```text
//! cargo +nightly fuzz run stun target/fuzz-corpus/stun fuzz/seeds/stun -- -max_total_time=600
//! ```
//!
//! Corpus policy (decision M1-36): `fuzz/seeds/stun/` holds the committed
//! seeds, the four RFC 5769 vectors and one error response, checked by
//! `tornect_net::stun::tests::the_fuzz_seeds_are_the_rfc_vectors`; campaigns
//! write to `target/fuzz-corpus/stun`.

#![no_main]

use std::net::{IpAddr, SocketAddr};

use libfuzzer_sys::fuzz_target;
use tornect_net::stun::{
    BINDING_ERROR, BINDING_SUCCESS, HEADER_LEN, StunReply, StunTxid, parse_response,
};
use tornect_net::udp::{STUN_COOKIE, STUN_MAX_LEN};

/// The transaction ID of the RFC 5769 §2.1–§2.3 vectors (the seeds).
const RFC_TXID: StunTxid = [
    0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
];

fn check(data: &[u8], txid: &StunTxid) {
    let Some(reply) = parse_response(data, txid) else {
        return;
    };
    assert!((HEADER_LEN..=STUN_MAX_LEN).contains(&data.len()));
    assert_eq!(&data[4..8], &STUN_COOKIE[..]);
    assert_eq!(&data[8..HEADER_LEN], &txid[..]);
    let length = usize::from(u16::from_be_bytes([data[2], data[3]]));
    assert_eq!(length, data.len() - HEADER_LEN);
    assert_eq!(length % 4, 0);
    let kind = u16::from_be_bytes([data[0], data[1]]);
    match reply {
        StunReply::Mapped(addr) => {
            assert_eq!(kind, BINDING_SUCCESS);
            redacted(addr, &format!("{reply:?}"));
        }
        StunReply::ErrorResponse => assert_eq!(kind, BINDING_ERROR),
    }
    let mut other = *txid;
    other[0] ^= 0x80;
    assert_eq!(parse_response(data, &other), None);
    for at in 4..HEADER_LEN {
        let mut flipped = data.to_vec();
        flipped[at] ^= 0x01;
        assert_eq!(parse_response(&flipped, txid), None, "byte {at}");
    }
}

/// The reply's `Debug` carries the family and class, not the address: its
/// only digit is the family's (`v4`, `v6`), and no four-digit group of an
/// IPv6 address appears in it (a group of letters only, such as `beef`).
fn redacted(addr: SocketAddr, text: &str) {
    let digits: String = text.chars().filter(char::is_ascii_digit).collect();
    assert!(digits == "4" || digits == "6", "{text}");
    if let IpAddr::V6(v6) = addr.ip() {
        for group in v6.segments().iter().map(|s| format!("{s:04x}")) {
            assert!(!text.contains(group.as_str()), "{group} in {text}");
        }
    }
}

fuzz_target!(|data: &[u8]| {
    check(data, &RFC_TXID);
    if data.len() >= HEADER_LEN {
        let mut own = [0; 12];
        own.copy_from_slice(&data[8..HEADER_LEN]);
        check(data, &own);
    }
});
