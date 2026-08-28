//! Tornect video codecs (`docs/PLAN.md` §A.2, §A.3 D8, §B.5): `Encoder` /
//! `Decoder` traits, runtime probing/scoring, FFmpeg hardware backends behind the
//! `ffmpeg` feature, and a software fallback that always compiles.
//!
//! Milestone 3 fills this crate in. `unsafe` is allowed only at FFI edges, each
//! block with a `// SAFETY:` comment.

#![deny(unsafe_code)]
