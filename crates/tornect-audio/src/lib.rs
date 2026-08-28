//! Tornect audio (`docs/PLAN.md` §A.3 D9, §B.4): capture (WASAPI loopback /
//! ScreenCaptureKit / PipeWire), Opus 48 kHz 10 ms frames with in-band FEC, and
//! playback via `cpal`.
//!
//! Milestone 5 fills this crate in. `unsafe` is allowed only at FFI edges, each
//! block with a `// SAFETY:` comment.

#![deny(unsafe_code)]
