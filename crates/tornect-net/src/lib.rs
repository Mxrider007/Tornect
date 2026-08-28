//! Tornect connectivity (`docs/PLAN.md` §A.3 D5–D7, §B.2): candidate gathering,
//! port mapping, STUN, simultaneous-open hole punching, quinn QUIC with key-pinned
//! TLS, and the Tor-tunnel fallback behind one `SessionTransport` trait.
//!
//! Milestone 2 fills this crate in. Nothing outside it may touch sockets or quinn.

#![forbid(unsafe_code)]
