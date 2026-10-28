//! The default STUN servers on the live internet (design `direct` §12.5
//! Phase B, §13 row 15, §5.4; decision M1-81): each entry of
//! `tornect_core::config::DEFAULT_STUN` is asked once, the way a session
//! asks it, and must answer with a global IPv4 mapped address.
//!
//! First the names are looked up the way the app does once Tor has
//! bootstrapped: one round of the background refresh
//! ([`RealNet::prefetch`], each name given
//! [`gather::PREFETCH_TIMEOUT`]), so that every session after it reads a
//! warm cache. Then each server goes through the session's own path: the
//! name through [`RealNet::resolve`] (answered from that cache), the address
//! through the session's [`StunFilter`](tornect_net::StunFilter), the bare
//! 20-byte Binding request out of a real session socket ([`PunchSocket`]),
//! and the reply back through the socket's STUN tee and the codec, taken
//! only from the address asked and only under its transaction ID
//! ([`gather::ask_stun`]). Nothing printed holds an address or a port: a
//! line names the entry, whether its name resolved, and what it answered
//! (`srflx` behind a NAT, `no-nat` on a public address).
//!
//! It fails in two different ways. A server that was asked (`requests` 1 or
//! more) and gave nothing global is silent: design §5.4 replaces such an
//! entry with one of another operator. A name that did not resolve in the
//! refresh round (`requests 0`) says nothing about the server: check this
//! machine's resolver and run it again before reading it as the server's.
//!
//! Ignored: it needs outbound UDP and DNS, which a build container lacks.
//! On the dev VM:
//!
//! ```text
//! cargo test -p tornect-net --test live_stun -- --ignored --nocapture
//! ```

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use quinn::AsyncUdpSocket as _;

use tornect_core::config::DEFAULT_STUN;
use tornect_net::gather::{self, StunAsk, StunOutcome};
use tornect_net::local::stun_filter;
use tornect_net::{NetEnv, ProbeGate, PunchSocket, RealNet, quic};

/// How long one server is given: more than the session's
/// [`gather::GATHER_BUDGET`] (its two requests and their answers), so that a
/// slow answer reads as slow, not as a dead server. The name is already in
/// the cache: no lookup is made in this time.
const PER_SERVER: Duration = Duration::from_secs(4);

/// How long the refresh round may take: each name
/// [`gather::PREFETCH_TIMEOUT`] at most, one after the other, and a margin.
const REFRESH_ROUND: Duration =
    Duration::from_secs(gather::PREFETCH_TIMEOUT.as_secs() * DEFAULT_STUN.len() as u64 + 5);

/// What one default server answered, in fixed words.
fn answered(outcome: StunOutcome) -> &'static str {
    match outcome {
        StunOutcome::Srflx(_) => "srflx",
        StunOutcome::NoNat => "no-nat",
        StunOutcome::Nothing => "nothing",
    }
}

#[tokio::test]
#[ignore = "live: outbound UDP and DNS (the dev VM), design `direct` §12.5"]
#[allow(clippy::print_stderr)] // the lines are the evidence
async fn every_default_stun_server_answers_a_bare_binding_request() {
    let net = RealNet::new();
    let addrs = net.interfaces().await.expect("the interface list");
    let sources = net.route_sources();
    assert!(
        sources.v4.is_some(),
        "no IPv4 route: STUN asks over IPv4 only"
    );
    let filter = stun_filter(&addrs, &sources, net.admit_loopback());
    // The app's lookups after bootstrap: one refresh round over the list,
    // then sessions read the cache (design §5.3).
    assert!(
        net.prefetch(|| DEFAULT_STUN.map(str::to_owned).to_vec()),
        "the refresh runs on this runtime"
    );
    let round = Instant::now();
    while !net.stun_dns().refreshed() {
        assert!(
            round.elapsed() < REFRESH_ROUND,
            "the refresh round did not end within {REFRESH_ROUND:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    eprintln!(
        "live_stun: the refresh round resolved {} of {} names in {} ms",
        net.stun_dns().len(),
        DEFAULT_STUN.len(),
        round.elapsed().as_millis()
    );
    let mut silent = Vec::new();
    let mut unresolved = Vec::new();
    let mut not_asked = Vec::new();
    for entry in DEFAULT_STUN {
        let cached = gather::server_name(entry)
            .is_some_and(|(host, port)| net.stun_dns().get(host, port).is_some());
        // A socket per server, as a session has one: a reply to an earlier
        // server's retransmission cannot be read as this one's.
        let bound = net.bind(None).expect("a session socket");
        let (socket, mut tees) = PunchSocket::new(bound, ProbeGate::new());
        // The tee fills only while quinn's endpoint driver polls the socket.
        let _endpoint = quic::endpoint(&socket, None).expect("an endpoint");
        let port = socket.local_addr().expect("its address").port();
        let hosts: Vec<SocketAddr> = addrs
            .iter()
            .filter(|a| a.ip.is_ipv4())
            .map(|a| SocketAddr::new(a.ip, port))
            .collect();
        let servers = [entry.to_owned()];
        let ask = StunAsk {
            servers: &servers,
            filter: &filter,
            hosts: &hosts,
            deadline: (tokio::time::Instant::now() + PER_SERVER).into_std(),
            draw: 0,
            tunnel: None,
        };
        let report = gather::ask_stun(&socket, &mut tees.stun, &net, &ask).await;
        let s = report.stats;
        eprintln!(
            "live_stun: {entry} {} (name {}; resolves {}, unresolved {}, requests {}, errors {}, \
             refused {}, ignored {})",
            answered(report.outcome),
            if cached { "resolved" } else { "not resolved" },
            s.resolves,
            s.unresolved,
            s.requests,
            s.errors,
            s.refused,
            s.ignored,
        );
        assert_eq!(
            u64::from(s.requests),
            socket.counters().stun_sent,
            "{entry}: every request left the session socket"
        );
        if report.outcome == StunOutcome::Nothing {
            if s.requests > 0 {
                silent.push(entry);
            } else if !cached {
                unresolved.push(entry);
            } else {
                not_asked.push(entry);
            }
        }
    }
    assert!(
        silent.is_empty(),
        "asked and no global answer from {silent:?}: design §5.4 replaces such an entry with \
         one of another operator"
    );
    assert!(
        not_asked.is_empty(),
        "the name of {not_asked:?} resolved, but no address passed the StunFilter (only a \
         global one does), so the server was never asked"
    );
    assert!(
        unresolved.is_empty(),
        "the name of {unresolved:?} did not resolve in the refresh round, so the server was \
         never asked: check this machine's resolver and run the test again; this alone is no \
         reason to replace the server"
    );
}
