//! Feeds arbitrary bytes through `tornect_signal::framing::read_frame`
//! (`docs/PLAN.md` §B.3: `u32`-BE length prefix, 64 KiB cap) and checks the
//! parser's invariants on whatever comes back; then through the signaling
//! channel's cancel-safe receive buffer (`Channel::frame_ready` and
//! `Channel::take_frame`, design `direct` §8.2 and §8.7) with read cut
//! points taken from the input, inside the 8 KiB handshake window and after
//! it.
//!
//! The input's first byte gives the number of cut bytes that follow it
//! (`% 16`); the rest is the stream. Cut or not, the channel must hand out
//! the same frames, in `msg_id` order, then the same end, and never write.
//!
//! ```text
//! cargo +nightly fuzz run framing -- -max_total_time=600
//! ```

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use tokio::runtime::Runtime;
use tornect_signal::framing::{FrameError, HEADER_LEN, MAX_FRAME_LEN, read_frame, write_frame};
use tornect_signal::fsm::HANDSHAKE_FRAME_CAP;
use tornect_signal::fsm::harness::{Took, channel_takes};

fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("current-thread runtime")
    })
}

/// `read_frame` on the whole input: one frame, bounded, re-encoding to the
/// bytes it consumed.
fn read_one(data: &[u8]) {
    runtime().block_on(async {
        let mut cursor = std::io::Cursor::new(data);
        match read_frame(&mut cursor).await {
            Ok(Some(payload)) => {
                // Bounded, consumed exactly one frame, and re-encodes to the same bytes.
                assert!(payload.len() <= MAX_FRAME_LEN);
                let consumed = usize::try_from(cursor.position()).expect("fits");
                assert_eq!(consumed, HEADER_LEN + payload.len());
                let mut encoded = Vec::new();
                write_frame(&mut encoded, &payload)
                    .await
                    .expect("Vec never fails");
                assert_eq!(encoded, &data[..consumed]);
            }
            Ok(None) => assert!(data.is_empty(), "clean EOF reported with unread bytes"),
            Err(FrameError::TooLarge { len, max }) => {
                assert!(len > MAX_FRAME_LEN);
                assert_eq!(max, MAX_FRAME_LEN);
            }
            Err(FrameError::Truncated) => assert!(!data.is_empty()),
            Err(other) => panic!("a cursor cannot fail: {other}"),
        }
    });
}

/// The channel's takes of `stream`, cut at `cuts` and uncut, with the window
/// open or closed: identical, frames first in `msg_id` order, each within the
/// cap and taken from the stream as it was, then exactly one end.
fn takes(stream: &[u8], cuts: &[u8], after_accept: bool) {
    let uncut = channel_takes(stream, &[], after_accept);
    let cut = channel_takes(stream, cuts, after_accept);
    assert_eq!(uncut, cut, "a cut changed what the channel took");
    let cap = if after_accept {
        MAX_FRAME_LEN
    } else {
        HANDSHAKE_FRAME_CAP
    };
    let (end, frames) = uncut.split_last().expect("the takes end");
    assert!(
        !matches!(end, Took::Frame { .. }),
        "the takes end with an end"
    );
    let mut at = 0usize;
    for (i, took) in frames.iter().enumerate() {
        let Took::Frame { msg_id, wire } = took else {
            panic!("an end before the last take: {took:?}");
        };
        assert_eq!(*msg_id, u64::try_from(i).expect("fits") + 1, "msg_id order");
        assert!(wire.len() <= HEADER_LEN + cap, "a frame over the cap");
        assert_eq!(
            &stream[at..at + wire.len()],
            &wire[..],
            "a frame not as sent"
        );
        at += wire.len();
    }
    if *end == Took::Eof {
        assert_eq!(at, stream.len(), "EOF with unread bytes");
    }
}

fuzz_target!(|data: &[u8]| {
    read_one(data);
    let Some((&n, rest)) = data.split_first() else {
        return;
    };
    let n = usize::from(n % 16).min(rest.len());
    let (cuts, stream) = rest.split_at(n);
    // An empty `cuts` means "uncut" to the harness: cut at one byte instead.
    let cuts = if cuts.is_empty() { &[1u8][..] } else { cuts };
    takes(stream, cuts, false);
    takes(stream, cuts, true);
});
