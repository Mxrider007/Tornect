//! F4 (`docs/PLAN.md` §B.8.15, §B.8.7.4): the IPC message codec of
//! `tornect_core::unattended::ipc` fed arbitrary bytes — every decoder must return
//! cleanly, in bounded time and allocation, and whatever it accepts must re-encode
//! within the wire bounds and decode back to the same value.
//!
//! ```text
//! cargo +nightly fuzz run ipc target/fuzz-corpus/ipc fuzz/seeds/ipc fuzz/corpus/ipc -- -max_total_time=600
//! ```
//!
//! Corpus policy (decision M1-36): `fuzz/seeds/ipc/` holds the committed seeds, the
//! three forms of `Show` (design `invite` §4.4), checked by
//! `tornect_core::unattended::ipc::tests::the_show_fuzz_seeds_decode_as_recorded`;
//! `fuzz/corpus/ipc/` is a `cmin` result; campaigns write to `target/fuzz-corpus/ipc`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tornect_core::unattended::ipc::{
    GrantOptions, LogPage, MAX_FRAME, MAX_PAYLOAD, PolicyInputsPayload, RegStartPayload,
    StatusReport, decode_payload, decode_request, decode_response, encode_payload, encode_request,
    encode_response,
};
use tornect_core::unattended::readiness::ReadinessSnapshot;

fn roundtrip_payload<T>(bytes: &[u8])
where
    T: for<'b> minicbor::Decode<'b, ()> + minicbor::Encode<()> + PartialEq + std::fmt::Debug,
{
    if let Ok(v) = decode_payload::<T>(bytes) {
        // Anything the decoder accepted encodes within the payload bound or is refused
        // by the encoder's own bound check — never a panic — and decodes back equal.
        if let Ok(again) = encode_payload(&v) {
            assert!(again.len() <= MAX_PAYLOAD);
            let back: T = decode_payload(&again).expect("re-decode of an encoded payload");
            assert_eq!(back, v);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    match decode_request(data) {
        Ok(req) => {
            // The request validated its bounds, so it re-encodes and round-trips.
            let bytes = encode_request(&req).expect("a decoded request re-encodes");
            assert!(bytes.len() <= MAX_FRAME);
            let back = decode_request(&bytes).expect("re-decode");
            assert_eq!(back, req);
            assert_eq!(back.op.tag(), req.op.tag());
            let _ = req.op.name();
            req.op.validate().expect("validated on decode");
        }
        Err(e) => {
            let _ = e.code();
        }
    }
    match decode_response(data) {
        Ok(resp) => {
            let bytes = encode_response(&resp).expect("a decoded response re-encodes");
            assert!(bytes.len() <= MAX_FRAME);
            assert_eq!(decode_response(&bytes).expect("re-decode"), resp);
        }
        Err(e) => {
            let _ = e.code();
        }
    }
    roundtrip_payload::<StatusReport>(data);
    roundtrip_payload::<LogPage>(data);
    roundtrip_payload::<GrantOptions>(data);
    roundtrip_payload::<PolicyInputsPayload>(data);
    roundtrip_payload::<RegStartPayload>(data);
    roundtrip_payload::<ReadinessSnapshot>(data);
    // The validators of the payload structs are total too.
    if let Ok(s) = decode_payload::<StatusReport>(data) {
        let _ = s.validate();
        let _ = s.readiness.host_not_ready_cause();
        let _ = s.readiness.badge();
    }
    if let Ok(p) = decode_payload::<LogPage>(data) {
        let _ = p.validate();
        // paging over the decoded lines with a fuzzed filter / cursor
        let filter = p.lines.first().cloned().unwrap_or_default();
        let filter: String = filter.chars().take(8).collect();
        let page = LogPage::page(&p.lines, &filter, p.next);
        page.validate().expect("a built page is within bounds");
        let bytes = encode_payload(&page).expect("a built page encodes");
        assert!(bytes.len() <= MAX_PAYLOAD);
    }
    if let Ok(i) = decode_payload::<PolicyInputsPayload>(data) {
        let _ = i.validate();
    }
    if let Ok(o) = decode_payload::<GrantOptions>(data) {
        let _ = o.validate();
    }
});
