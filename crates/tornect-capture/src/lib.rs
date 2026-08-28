//! Tornect screen capture (`docs/PLAN.md` §B.5): the `VideoCaptureSource` trait
//! and per-OS backends (`pipewire`, `wgc`, `sckit` cargo features) plus a
//! synthetic test-pattern source so the pipeline runs anywhere.
//!
//! Milestone 3 (dev OS) and Milestone 6 (parity) fill this crate in. `unsafe` is
//! allowed only at FFI edges, each block with a `// SAFETY:` comment.

#![deny(unsafe_code)]
