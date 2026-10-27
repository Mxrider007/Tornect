//! The wire form of a candidate batch (the direct design §6.1, §8.5): this
//! side's candidates as `CANDIDATES` frames, a peer's frame as the batch and
//! the scope the direct link takes.
//!
//! The file depends on `std`, `tornect-net` and `tornect-signal`'s
//! messages only: the `candidates` fuzz target compiles it as it is, so the
//! code it fuzzes is the code a session runs.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use tornect_net::{Candidate, CandidateKind, Scope, canon_ip};
use tornect_signal::messages::{self, MAX_CANDIDATES_PER_FRAME, candidate_kind};

/// `batch` as the `CANDIDATES` frames that carry it, at most
/// [`MAX_CANDIDATES_PER_FRAME`] candidates each, every frame with `scope`
/// (the direct design §4, §6.1): IPv4 as 4 bytes (never v4-mapped), IPv6 as
/// 16. A peer-reflexive candidate is local only and never sent, nor is a
/// candidate without a port.
#[must_use]
pub fn to_wire(batch: &[Candidate], scope: Scope) -> Vec<messages::Candidates> {
    let code = match scope {
        Scope::SameSite => messages::scope::SAME_SITE,
        Scope::Internet => messages::scope::INTERNET,
    };
    let wire: Vec<messages::Candidate> = batch
        .iter()
        .filter_map(|c| {
            let kind = match c.kind {
                CandidateKind::Host => candidate_kind::HOST,
                CandidateKind::Srflx => candidate_kind::SRFLX,
                CandidateKind::Mapped => candidate_kind::MAPPED,
                CandidateKind::Prflx => return None,
            };
            let ip = match canon_ip(c.addr.ip()) {
                IpAddr::V4(v4) => v4.octets().to_vec(),
                IpAddr::V6(v6) => v6.octets().to_vec(),
            };
            (c.addr.port() != 0).then(|| messages::Candidate {
                kind,
                ip,
                port: c.addr.port(),
            })
        })
        .collect();
    wire.chunks(MAX_CANDIDATES_PER_FRAME)
        .map(|chunk| messages::Candidates {
            candidates: chunk.to_vec(),
            scope: Some(code),
        })
        .collect()
}

/// A peer's `CANDIDATES` frame as the direct link takes it: its candidates
/// and its scope (the direct design §4, §6.1). A candidate of a kind this
/// build does not know, a v4-mapped IPv6 address, an address of another
/// length or port 0 is dropped; an absent or unknown scope is
/// [`Scope::SameSite`].
#[must_use]
pub fn from_wire(frame: &messages::Candidates) -> (Vec<Candidate>, Scope) {
    let scope = if frame.internet() {
        Scope::Internet
    } else {
        Scope::SameSite
    };
    let batch = frame
        .candidates
        .iter()
        .filter_map(|c| {
            let kind = match c.kind {
                candidate_kind::HOST => CandidateKind::Host,
                candidate_kind::SRFLX => CandidateKind::Srflx,
                candidate_kind::MAPPED => CandidateKind::Mapped,
                _ => return None,
            };
            let ip = if let Ok(v4) = <[u8; 4]>::try_from(c.ip.as_slice()) {
                IpAddr::from(v4)
            } else {
                let v6 = Ipv6Addr::from(<[u8; 16]>::try_from(c.ip.as_slice()).ok()?);
                if v6.to_ipv4_mapped().is_some() {
                    return None;
                }
                IpAddr::V6(v6)
            };
            (c.port != 0).then(|| Candidate {
                kind,
                addr: SocketAddr::new(ip, c.port),
            })
        })
        .collect();
    (batch, scope)
}
