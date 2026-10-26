//! The direct-path signaling bodies (design `direct` §6.1 and §8.7, decision
//! M1-80) fed arbitrary bytes: `decode_body` of `CANDIDATES`, `TOR_FALLBACK`
//! and `CANDIDATES_DONE` returns, and whatever it accepts
//!
//! - has the §6.1 shape: 1 to 8 candidates, each with a 4- or 16-byte ip that
//!   is not v4-mapped and a non-zero port (`Body::validate`);
//! - decodes back to itself once re-encoded (unknown keys are dropped, so the
//!   bytes need not match);
//! - reads its scope and reason the way the receivers do (an unknown scope is
//!   same-site, an unknown reason is named "unknown");
//! - prints no ip and no port through `Debug` (decision M1-83).
//!
//! Later steps of the design extend the target with the session's
//! `from_wire` and `tornect-net`'s `RemoteFilter::admit` once they exist.
//!
//! ```text
//! cargo +nightly fuzz run candidates target/fuzz-corpus/candidates fuzz/seeds/candidates -- -max_total_time=600
//! ```
//!
//! Corpus policy (decision M1-36): `fuzz/seeds/candidates/` holds the committed
//! seeds, the golden bodies of §6.1 and a full frame, checked by
//! `tornect_signal::messages::tests::the_fuzz_seeds_are_the_golden_path_bodies`;
//! campaigns write to `target/fuzz-corpus/candidates`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tornect_signal::messages::{
    Candidates, CandidatesDone, MAX_CANDIDATES_PER_FRAME, TorFallback, decode_body, encode_body,
    fallback, scope,
};

/// The prefix of a v4-mapped IPv6 address (`::ffff:0:0/96`).
const V4_MAPPED: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];

fn candidates(data: &[u8]) {
    let Ok(frame) = decode_body::<Candidates>(data) else {
        return;
    };
    assert!(
        (1..=MAX_CANDIDATES_PER_FRAME).contains(&frame.candidates.len()),
        "{} candidates",
        frame.candidates.len()
    );
    for c in &frame.candidates {
        match c.ip.len() {
            4 => {}
            16 => assert!(!c.ip.starts_with(&V4_MAPPED), "a v4-mapped ip"),
            n => panic!("a {n}-byte ip"),
        }
        assert_ne!(c.port, 0, "port 0");
    }
    assert_eq!(frame.internet(), frame.scope_code() == scope::INTERNET);
    assert_eq!(frame.scope_code(), frame.scope.unwrap_or(scope::SAME_SITE));
    let back: Candidates = decode_body(&encode_body(&frame)).expect("re-encoded frame");
    assert_eq!(back, frame);
    let text = format!("{frame:?}");
    assert!(!text.contains("ip") && !text.contains("port"), "{text}");
}

fn tor_fallback(data: &[u8]) {
    let Ok(fb) = decode_body::<TorFallback>(data) else {
        return;
    };
    if let Some(code) = fb.reason {
        let name = fallback::name(code);
        assert_eq!(
            name == "unknown",
            !(1..=8).contains(&code),
            "{code}: {name}"
        );
    }
    let back: TorFallback = decode_body(&encode_body(&fb)).expect("re-encoded fallback");
    assert_eq!(back, fb);
}

fn done(data: &[u8]) {
    if let Ok(d) = decode_body::<CandidatesDone>(data) {
        assert_eq!(encode_body(&d), [0xA0]);
    }
}

fuzz_target!(|data: &[u8]| {
    candidates(data);
    tor_fallback(data);
    done(data);
});
