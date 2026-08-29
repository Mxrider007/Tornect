//! Feeds arbitrary bytes through `tornect_signal::framing::read_frame`
//! (`docs/PLAN.md` §B.3: `u32`-BE length prefix, 64 KiB cap) and checks the
//! parser's invariants on whatever comes back.
//!
//! ```text
//! cargo +nightly fuzz run framing -- -max_total_time=600
//! ```

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use tokio::runtime::Runtime;
use tornect_signal::framing::{FrameError, HEADER_LEN, MAX_FRAME_LEN, read_frame, write_frame};

fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("current-thread runtime")
    })
}

fuzz_target!(|data: &[u8]| {
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
});
