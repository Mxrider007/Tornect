//! The session services stream's frames (`tornect_proto::services`, decision
//! M1-76, the services design §3) fed arbitrary bytes:
//!
//! - `SvcMsg::decode` of every type: it returns, what it accepts passes
//!   `validate` and decodes back to itself once re-encoded, and a hand-packed
//!   body re-encodes to exactly its bytes;
//! - the gated reader of both sides (`read_header`, `ty::gate`, `skip_body`,
//!   `read_body_max` at `ty::max_body`), under the cap sets a session can
//!   have (everything, view-only chat, files and clipboard turned off, paused,
//!   nothing but the clipboard): a frame is decoded only when its cap was
//!   granted, a refused frame's body is never read, and every frame stays
//!   within its bounds;
//! - `read_bind`, which reads 53 bytes at most;
//! - the clipboard assembler (`ClipAssembly`, design step 18) fed the
//!   clipboard frames each gated reader decodes, and told of the ones it
//!   skips: it never panics, and a whole text is exactly as long as its
//!   `ClipStart` said.
//!
//! The session's own reader (`tornect-session`'s, the same gate in a task)
//! is covered by its unit tests; this crate does not build the session.
//!
//! ```text
//! cargo +nightly fuzz run services target/fuzz-corpus/services fuzz/seeds/services -- -max_total_time=600
//! ```
//!
//! Corpus policy (decision M1-36): `fuzz/seeds/services/` holds the committed
//! seeds, one whole frame (length prefix included) of each of the 21 types,
//! checked by `tornect_proto::services::tests::the_fuzz_seeds_are_one_frame_of_each_message`;
//! campaigns write to `target/fuzz-corpus/services`.

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use tokio::runtime::Runtime;
use tornect_proto::services::{
    BIND_LEN, ClipAssembly, MAX_CLIP, MAX_SERVICES_FRAME, Side, SvcError, SvcMsg, caps, read_bind,
    read_body_max, read_header, skip_body, ty,
};

fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("current-thread runtime")
    })
}

/// Whether a type's body is hand-packed (its bytes are canonical).
fn packed(t: u8) -> bool {
    matches!(
        t,
        ty::BIND | ty::REFUSED | ty::CLIP_CHUNK | ty::DATA | ty::CREDIT | ty::CLOSE
    )
}

/// A body `decode` accepted is valid and stable under a re-encode.
fn decoded(t: u8, body: &[u8]) {
    if let Ok(msg) = SvcMsg::decode(t, body) {
        assert!(msg.validate().is_ok(), "{msg:?}");
        assert_eq!(msg.ty(), t);
        let bytes = msg.encode();
        assert!(bytes.len() - 4 <= MAX_SERVICES_FRAME, "{msg:?}");
        if packed(t) {
            assert_eq!(&bytes[5..], body, "{msg:?}");
        }
        assert_eq!(SvcMsg::decode(t, &bytes[5..]).expect("re-decodes"), msg);
    }
}

/// The cap sets a reader can hold: (granted, off, paused).
const STATES: [(u16, u16, u16); 5] = [
    (caps::ALL, 0, 0),
    (caps::CHAT, 0, 0),
    (caps::ALL, caps::PAUSABLE, 0),
    (caps::ALL, 0, caps::PAUSABLE),
    (caps::CLIP, 0, caps::CLIP),
];

/// Read `data` as one side's stream past the bind, gating every frame.
async fn gated(data: &[u8], from: Side, (granted, off, paused): (u16, u16, u16)) {
    let mut cursor = std::io::Cursor::new(data);
    let mut scratch = [0u8; 512];
    let mut clip = ClipAssembly::default();
    let mut lens = std::collections::HashMap::new();
    loop {
        let header = match read_header(&mut cursor).await {
            Ok(Some(header)) => header,
            Ok(None) => break,
            Err(SvcError::Size(len)) => {
                assert!(len == 0 || len > MAX_SERVICES_FRAME, "refused {len}");
                break;
            }
            Err(_) => break,
        };
        assert!(header.len < MAX_SERVICES_FRAME);
        let at = cursor.position();
        match ty::gate(header.ty, from, granted, off, paused) {
            ty::Gate::Close(reason) => {
                // Refused on the type alone: nothing of the body was read.
                assert_eq!(cursor.position(), at);
                let needs = ty::needs(header.ty, from);
                match needs {
                    None => assert_eq!(reason, tornect_proto::services::reason::PROTOCOL),
                    Some(n) => assert!(n != 0 && n & granted == 0),
                }
                break;
            }
            ty::Gate::Skip => {
                if skip_body(&mut cursor, header, &mut scratch).await.is_err() {
                    break;
                }
                assert_eq!(cursor.position(), at + header.len as u64);
                if matches!(header.ty, ty::CLIP_START | ty::CLIP_CHUNK) {
                    clip.ignore_rest();
                }
            }
            ty::Gate::Decode => {
                let needs = ty::needs(header.ty, from).expect("a decoded type is expected");
                assert!(
                    needs == 0 || needs & granted & !off != 0,
                    "decoded a cap not held"
                );
                let max = ty::max_body(header.ty).expect("a known type");
                let body = match read_body_max(&mut cursor, header, max).await {
                    Ok(body) => body,
                    Err(_) => break,
                };
                let msg = match SvcMsg::decode(header.ty, &body) {
                    Ok(msg) => msg,
                    Err(_) => break,
                };
                assert_eq!(msg.ty(), header.ty);
                // The session's receiver: a text whose `seq` is odd is not
                // taken (its rate or its switch), the others are.
                let assembled = match msg {
                    SvcMsg::ClipStart(start) => clip
                        .start(start, start.seq % 2 == 0, MAX_CLIP)
                        .map(|()| {
                            lens.insert(start.seq, start.len as usize);
                        })
                        .is_ok(),
                    SvcMsg::ClipChunk { seq, offset, bytes } => {
                        match clip.chunk(seq, offset, &bytes) {
                            Ok(Some(whole)) => {
                                assert_eq!(Some(&whole.len()), lens.get(&seq));
                                true
                            }
                            Ok(None) => true,
                            Err(_) => false,
                        }
                    }
                    _ => true,
                };
                // Out of order: the session ends the stream here.
                if !assembled {
                    break;
                }
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    // A type byte and a body, and the shape of the seeds past their prefix.
    if let Some((&t, body)) = data.split_first() {
        decoded(t, body);
    }
    if let Some((&t, body)) = data.get(4..).and_then(<[u8]>::split_first) {
        decoded(t, body);
    }
    runtime().block_on(async {
        for from in [Side::Viewer, Side::Host] {
            for state in STATES {
                gated(data, from, state).await;
            }
        }
        // The bind: at most its fixed size is read, whatever follows.
        let mut cursor = std::io::Cursor::new(data);
        let bound = read_bind(&mut cursor).await;
        assert!(cursor.position() <= 4 + BIND_LEN as u64);
        if let Ok(bind) = bound {
            assert_eq!(cursor.position(), 4 + BIND_LEN as u64);
            assert_eq!(SvcMsg::Bind(bind).encode(), &data[..4 + BIND_LEN]);
        }
    });
});
