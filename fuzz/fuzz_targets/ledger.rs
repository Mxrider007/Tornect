//! The router-port ledger loader (design `direct` §7.4 "Ledger", decisions
//! M1-81 and M1-83; `docs/PLAN.md` §D.5) fed arbitrary bytes: the list a
//! start-up sweep and `doctor` read from `<state>/router-ports/`.
//! `decode_list` never panics, ends in time bounded by the input's length
//! whatever array length its header declares, and whatever it returns
//!
//! - holds at most `MAX_LEDGER_ENTRIES` entries, each one this code can act
//!   on (a non-zero internal port, a nonce for PCP, no zero external port);
//! - counts at most one drop per byte, plus one;
//! - encodes back to a list that decodes to the same entries with no drop;
//! - prints the protocol and the address classes only through `Debug`
//!   (decision M1-83): its only digits are the two `v4` of the class names.
//!
//! ```text
//! cargo +nightly fuzz run ledger target/fuzz-corpus/ledger fuzz/seeds/ledger -- -max_total_time=600
//! ```
//!
//! Corpus policy (decision M1-36): `fuzz/seeds/ledger/` holds the committed
//! seeds, checked by
//! `tornect_net::mapping::ledger::tests::the_fuzz_seeds_are_these_lists`;
//! campaigns write to `target/fuzz-corpus/ledger`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tornect_net::mapping::{MAX_LEDGER_ENTRIES, MapVia, decode_list, encode_list};

fuzz_target!(|data: &[u8]| {
    let (entries, dropped) = decode_list(data);
    assert!(entries.len() <= MAX_LEDGER_ENTRIES);
    assert!(dropped <= data.len() + 1, "{dropped} drops of {} bytes", data.len());
    for entry in &entries {
        assert_ne!(entry.internal_port, 0);
        assert!(entry.via != MapVia::Pcp || entry.pcp_nonce.is_some());
        assert_ne!(entry.external_port, Some(0));
        let text = format!("{entry:?}");
        let digits: String = text.chars().filter(char::is_ascii_digit).collect();
        assert_eq!(digits, "44", "{text}");
    }
    assert_eq!(decode_list(&encode_list(&entries)), (entries, 0));
});
