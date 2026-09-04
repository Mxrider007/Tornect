//! F1 (`docs/PLAN.md` §B.8.15): the envelope decoder, every body decoder and
//! both handshake FSMs fed with arbitrary frames must never panic, in bounded
//! time and allocation.
//!
//! ```text
//! cargo +nightly fuzz run envelope target/fuzz-corpus/envelope fuzz/seeds/envelope fuzz/corpus/envelope -- -max_total_time=600
//! ```
//!
//! Corpus policy (decision M1-36): `fuzz/seeds/envelope/` holds the eight
//! committed, test-checked seeds; `fuzz/corpus/envelope/` is the committed
//! corpus, replaced only by a `cargo +nightly fuzz cmin envelope` result
//! (never raw libFuzzer scratch — note that with `cargo fuzz cmin` any extra
//! `-- <dir>` argument precedes `-merge=1` and therefore becomes the merge
//! *output*); ad-hoc campaigns write to `target/fuzz-corpus/envelope`.
//!
//! The whole harness lives in `tornect_signal::fsm::harness` (so the unit
//! test `fsm::golden::fuzz_seeds_match_the_golden_vectors_and_reach_a_session`
//! proves what it reaches): the first input byte selects one of eight
//! scenarios — host or client FSM, paired or not, frames sent raw or
//! re-signed by the fixed peer key over the running transcript — and the rest
//! is split into `u16`-BE length-prefixed frames. Time is paused, so every
//! §B.8.4.5 timer fires instantly once the input is exhausted, and no store
//! ever touches the disk (ephemeral stores).

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use tokio::runtime::Runtime;
use tornect_signal::envelope::{Envelope, Kind};
use tornect_signal::fsm::harness::{self, Scenario};
use tornect_signal::messages::decode_any;

fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .expect("current-thread runtime")
    })
}

fuzz_target!(|data: &[u8]| {
    // Every decoder on the raw input.
    let _ = Envelope::decode(data);
    for kind in Kind::ALL {
        let _ = decode_any(kind, data);
    }
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let frames = harness::split_frames(rest);
    let _ = runtime().block_on(harness::run(Scenario::from_byte(mode), frames));
});
