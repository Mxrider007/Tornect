//! Tornect signaling (`docs/PLAN.md` §B.3): embedded Arti onion service, CBOR
//! envelope protocol, pairing with SAS, and unattended-access authentication (§B.8).
//!
//! Milestone 1 fills this crate in. Nothing outside it may import Arti.

#![forbid(unsafe_code)]

pub use tornect_core::PROTOCOL_VERSION;
