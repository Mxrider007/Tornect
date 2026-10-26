//! The Tor media stream's frames (`tornect_proto`, decision M1-39; the quality
//! design's §4 messages; the monitors design's §3 `SelectMonitor` and `Monitors`,
//! decision M1-75; the direct design's §6.6 `BindProof`) fed arbitrary bytes:
//! `Msg::decode` and the stream reader
//! `read_msg_max` at both caps return cleanly, in bounded allocation, and whatever
//! they accept encodes back to exactly the bytes it was read from (the byte-level
//! canonical form: a monitor message's every rule is checked when decoding, so an
//! accepted one also passes the encoder's own check).
//!
//! ```text
//! cargo +nightly fuzz run media target/fuzz-corpus/media fuzz/seeds/media -- -max_total_time=600
//! ```
//!
//! Corpus policy (decision M1-36): `fuzz/seeds/media/` holds the committed seeds, one
//! whole frame (length prefix included) of each message, checked by
//! `tornect_proto::tests::the_fuzz_seeds_are_one_frame_of_each_message`; campaigns
//! write to `target/fuzz-corpus/media`.

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use tokio::runtime::Runtime;
use tornect_proto::{MAX_CLIENT_FRAME, MAX_FRAME, Msg, ProtoError, read_msg_max};

fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("current-thread runtime")
    })
}

/// A frame `decode` accepted is the canonical encoding of what it returned.
fn decoded(frame: &[u8]) {
    if let Ok(msg) = Msg::decode(frame) {
        let bytes = msg.encode();
        assert_eq!(&bytes[4..], frame, "{msg:?}");
    }
}

fuzz_target!(|data: &[u8]| {
    // The bytes as `read_msg` hands them to `decode`: a type byte and a body.
    decoded(data);
    // And past a length prefix, the shape of the committed seeds.
    if let Some(frame) = data.get(4..) {
        decoded(frame);
    }
    // The stream reader at the host's cap for the viewer's direction and at the
    // viewer's: every frame it returns stays under the cap and re-encodes to the
    // bytes it consumed; it stops at the end or at the first error.
    for cap in [MAX_CLIENT_FRAME, MAX_FRAME] {
        runtime().block_on(async {
            let mut cursor = std::io::Cursor::new(data);
            loop {
                let start = usize::try_from(cursor.position()).expect("fits");
                match read_msg_max(&mut cursor, cap).await {
                    Ok(Some(msg)) => {
                        let end = usize::try_from(cursor.position()).expect("fits");
                        let bytes = msg.encode();
                        assert!(bytes.len() - 4 <= cap, "{msg:?} over {cap}");
                        assert_eq!(bytes, &data[start..end], "{msg:?}");
                    }
                    // The end, or a length prefix cut short by it, which the
                    // reader also takes for the stream's end.
                    Ok(None) => {
                        assert!(data.len() - start < 4, "an end with a whole prefix unread");
                        break;
                    }
                    Err(ProtoError::Size(len)) => {
                        assert!(len == 0 || len > cap, "refused a {len}-byte frame under {cap}");
                        break;
                    }
                    Err(_) => break,
                }
            }
        });
    }
});
