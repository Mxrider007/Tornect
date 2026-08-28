//! Tornect media wire protocol (`docs/PLAN.md` §B.4): datagram headers,
//! fragmentation/reassembly, FEC, jitter buffer, pacer, ABR controller and stats.
//!
//! Pure Rust, no I/O: it operates on byte buffers and clocks handed to it, so
//! every component is unit- and property-testable. Milestone 3 fills it in.

#![forbid(unsafe_code)]
