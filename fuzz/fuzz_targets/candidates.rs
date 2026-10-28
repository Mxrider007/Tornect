//! The direct-path signaling bodies (design `direct` §6.1 and §8.7, decision
//! M1-80) fed arbitrary bytes: `decode_body` of `CANDIDATES`, `TOR_FALLBACK`
//! and `CANDIDATES_DONE` returns, and whatever it accepts
//!
//! - has the §6.1 shape: 1 to 8 candidates, each with a 4- or 16-byte ip that
//!   is not v4-mapped and a non-zero port (`Body::validate`);
//! - decodes back to itself once re-encoded (unknown keys are dropped, so the
//!   bytes need not match);
//! - reads its scope and reason the way the receivers do (an unknown scope is
//!   same-site, an unknown reason is named "unknown");
//! - prints no ip and no port through `Debug` (decision M1-83);
//! - goes on as a session takes it (design §8.7): the session's own
//!   `from_wire` (`crates/tornect-session/src/direct/wire.rs`, compiled here
//!   as it is) keeps only known kinds with a canonical address and a port,
//!   in the frame's scope, and `to_wire` sends that batch back as frames
//!   that validate and read back to it; then each candidate meets the
//!   `RemoteFilter` that `tornect-net`'s `local::remote_filter` builds for
//!   one fixed computer (a private IPv4, a ULA and a global IPv6 on one
//!   physical interface), in both scopes, with and without a dual-stack
//!   socket. Whatever it admits has a port a peer may use, is not this
//!   computer's, is private, unique-local or global (never loopback,
//!   link-local, carrier-grade NAT space or an unusable range), is IPv6
//!   only on a dual-stack socket, is global IPv6 only when a global IPv6
//!   was offered, and in same-site scope is on this computer's site.
//!
//! ```text
//! cargo +nightly fuzz run candidates target/fuzz-corpus/candidates fuzz/seeds/candidates -- -max_total_time=600
//! ```
//!
//! Corpus policy (decision M1-36): `fuzz/seeds/candidates/` holds the committed
//! seeds, the golden bodies of §6.1 and a full frame, checked by
//! `tornect_signal::messages::tests::the_fuzz_seeds_are_the_golden_path_bodies`;
//! campaigns write to `target/fuzz-corpus/candidates`.

#![no_main]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use libfuzzer_sys::fuzz_target;
use tornect_net::addr::{MIN_REMOTE_PORT, REFUSED_PORTS};
use tornect_net::local::{remote_filter, select_host_candidates};
use tornect_net::{
    AddrClass, CandidateKind, IfaceAddr, IfaceKind, RemoteFilter, RouteSources, Scope, canon, class,
};
use tornect_signal::messages::{
    Body as _, Candidates, CandidatesDone, MAX_CANDIDATES_PER_FRAME, TorFallback, decode_body,
    encode_body, fallback, scope,
};

/// The session's wire form of a candidate batch, compiled from its source
/// (it names only `std`, `tornect-net` and `tornect-signal`).
#[path = "../../crates/tornect-session/src/direct/wire.rs"]
mod wire;

/// The prefix of a v4-mapped IPv6 address (`::ffff:0:0/96`).
const V4_MAPPED: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];

/// The fixed computer's addresses: a private IPv4 (the IPv4 route source),
/// a temporary ULA and a temporary global IPv6 (the IPv6 route source), all
/// on one physical interface.
const OWN_V4: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 20);
const OWN_ULA: Ipv6Addr = Ipv6Addr::new(0xfd12, 0x3456, 0x789a, 1, 0, 0, 0, 0x20);
const OWN_GLOBAL_V6: Ipv6Addr = Ipv6Addr::new(0x2a01, 0x4f8, 1, 2, 0, 0, 0, 0x20);

/// The port of the fixed computer's offered candidates.
const OWN_PORT: u16 = 50_000;

fn iface_addr(ip: IpAddr, prefix_len: u8) -> IfaceAddr {
    IfaceAddr {
        ip,
        prefix_len,
        class: class(ip),
        temporary: ip.is_ipv6(),
        deprecated: false,
        tentative: false,
        duplicated: false,
        eui64: false,
        iface_index: 2,
        iface_kind: IfaceKind::Physical,
        up: true,
        gateway_v4: None,
    }
}

/// The fixed computer's `RemoteFilter` in `scope`, as a session builds it
/// from its interfaces, its route sources and the host candidates it
/// offered; the filter and whether a global IPv6 was offered.
fn machine_filter(scope: Scope, dual_stack: bool) -> (RemoteFilter, bool) {
    let addrs = [
        iface_addr(IpAddr::V4(OWN_V4), 24),
        iface_addr(IpAddr::V6(OWN_ULA), 64),
        iface_addr(IpAddr::V6(OWN_GLOBAL_V6), 64),
    ];
    let sources = RouteSources {
        v4: Some(OWN_V4),
        v6: Some(OWN_GLOBAL_V6),
    };
    let offered = select_host_candidates(&addrs, &sources, OWN_PORT, scope, false);
    let global_v6 = dual_stack
        && offered
            .iter()
            .any(|c| c.addr.ip() == IpAddr::V6(OWN_GLOBAL_V6));
    let filter = remote_filter(scope, &addrs, &sources, &offered, dual_stack, None, false);
    (filter, global_v6)
}

/// A decoded frame through the session's `from_wire` and `to_wire`, then
/// each candidate through the fixed computer's filters.
fn as_a_session_takes_it(frame: &Candidates) {
    let (batch, got) = wire::from_wire(frame);
    let want = if frame.internet() {
        Scope::Internet
    } else {
        Scope::SameSite
    };
    assert_eq!(got, want, "the frame's scope");
    assert!(
        batch.len() <= frame.candidates.len(),
        "more candidates out than in"
    );
    for c in &batch {
        assert_ne!(
            c.kind,
            CandidateKind::Prflx,
            "a peer-reflexive candidate off the wire"
        );
        assert_eq!(canon(c.addr), c.addr, "a v4-mapped address kept");
        assert_ne!(c.addr.port(), 0, "port 0 kept");
    }
    let frames = wire::to_wire(&batch, got);
    assert_eq!(frames.is_empty(), batch.is_empty(), "frames for no batch");
    let mut back = Vec::new();
    for f in &frames {
        f.validate().expect("a frame to_wire makes is valid");
        let (part, scope) = wire::from_wire(f);
        assert_eq!(scope, got, "to_wire's scope");
        back.extend(part);
    }
    assert_eq!(back, batch, "to_wire then from_wire");

    for scope in [Scope::SameSite, Scope::Internet] {
        for dual_stack in [false, true] {
            let (filter, global_v6) = machine_filter(scope, dual_stack);
            for c in &batch {
                let addr = c.addr;
                assert_eq!(
                    filter.admit(addr),
                    filter.check(addr).is_ok(),
                    "admit and check"
                );
                if !filter.admit(addr) {
                    continue;
                }
                let ip = addr.ip();
                assert!(
                    addr.port() >= MIN_REMOTE_PORT && !REFUSED_PORTS.contains(&addr.port()),
                    "an admitted port below the floor or refused"
                );
                assert!(
                    ip != IpAddr::V4(OWN_V4)
                        && ip != IpAddr::V6(OWN_ULA)
                        && ip != IpAddr::V6(OWN_GLOBAL_V6),
                    "this computer's own address admitted"
                );
                let cls = class(ip);
                assert!(
                    matches!(
                        cls,
                        AddrClass::Private | AddrClass::UniqueLocal | AddrClass::Global
                    ),
                    "admitted class {cls:?}"
                );
                if ip.is_ipv6() {
                    assert!(dual_stack, "IPv6 admitted without a dual-stack socket");
                }
                if cls == AddrClass::Global && ip.is_ipv6() {
                    assert!(global_v6, "a global IPv6 admitted with none offered");
                }
                if scope == Scope::SameSite {
                    assert!(filter.on_site(ip), "same-site scope admitted another site");
                }
            }
        }
    }
}

fn candidates(data: &[u8]) {
    let Ok(frame) = decode_body::<Candidates>(data) else {
        return;
    };
    assert!(
        (1..=MAX_CANDIDATES_PER_FRAME).contains(&frame.candidates.len()),
        "{} candidates",
        frame.candidates.len()
    );
    for c in &frame.candidates {
        match c.ip.len() {
            4 => {}
            16 => assert!(!c.ip.starts_with(&V4_MAPPED), "a v4-mapped ip"),
            n => panic!("a {n}-byte ip"),
        }
        assert_ne!(c.port, 0, "port 0");
    }
    assert_eq!(frame.internet(), frame.scope_code() == scope::INTERNET);
    assert_eq!(frame.scope_code(), frame.scope.unwrap_or(scope::SAME_SITE));
    let back: Candidates = decode_body(&encode_body(&frame)).expect("re-encoded frame");
    assert_eq!(back, frame);
    let text = format!("{frame:?}");
    assert!(!text.contains("ip") && !text.contains("port"), "{text}");
    as_a_session_takes_it(&frame);
}

fn tor_fallback(data: &[u8]) {
    let Ok(fb) = decode_body::<TorFallback>(data) else {
        return;
    };
    if let Some(code) = fb.reason {
        let name = fallback::name(code);
        assert_eq!(
            name == "unknown",
            !(1..=8).contains(&code),
            "{code}: {name}"
        );
    }
    let back: TorFallback = decode_body(&encode_body(&fb)).expect("re-encoded fallback");
    assert_eq!(back, fb);
}

fn done(data: &[u8]) {
    if let Ok(d) = decode_body::<CandidatesDone>(data) {
        assert_eq!(encode_body(&d), [0xA0]);
    }
}

fuzz_target!(|data: &[u8]| {
    candidates(data);
    tor_fallback(data);
    done(data);
});
