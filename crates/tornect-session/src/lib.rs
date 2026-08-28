//! Tornect session orchestration (`docs/PLAN.md` §B.1, §B.2): the host and client
//! state machines that wire signaling (consent, pairing, unattended auth),
//! connectivity (punch or Tor fallback) and the media pipeline together.
//!
//! Milestone 4 fills this crate in. Consent gating is structural: a session
//! cannot be constructed without a consent grant or a verified unattended proof.

#![forbid(unsafe_code)]
