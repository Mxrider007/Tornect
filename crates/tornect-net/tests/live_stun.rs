//! The default STUN servers on the live internet (design `direct` §12.5
//! Phase B, §13 row 15, §5.4; decision M1-81): each entry of
//! `tornect_core::config::DEFAULT_STUN` is asked once, the way a session
//! asks it, and must answer with a global IPv4 mapped address.
//!
//! Each server goes through the session's own path: the name through
//! [`RealNet::resolve`] (a fresh machine's cache is cold, so the system
//! resolver is asked once per name), the address through the session's
//! [`StunFilter`](tornect_net::StunFilter), the bare 20-byte Binding request
//! out of a real session socket ([`PunchSocket`]), and the reply back
//! through the socket's STUN tee and the codec, taken only from the address
//! asked and only under its transaction ID ([`gather::ask_stun`]). Nothing
//! printed holds an address or a port: a line names the entry and what it
//! answered (`srflx` behind a NAT, `no-nat` on a public address).
//!
//! Ignored: it needs outbound UDP and DNS, which a build container lacks.
//! On the dev VM:
//!
//! ```text
//! cargo test -p tornect-net --test live_stun -- --ignored --nocapture
//! ```

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::time::Duration;

use quinn::AsyncUdpSocket as _;

use tornect_core::config::DEFAULT_STUN;
use tornect_net::gather::{self, StunAsk, StunOutcome};
use tornect_net::local::stun_filter;
use tornect_net::{NetEnv, ProbeGate, PunchSocket, RealNet, quic};

/// How long one server is given: the session's [`gather::GATHER_BUDGET`]
/// (its two requests and their answers), plus the one name lookup a cold
/// cache makes ([`gather::DNS_TIMEOUT`] in a session; more here, where a
/// slow resolver should read as slow, not as a dead server).
const PER_SERVER: Duration = Duration::from_secs(4);

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
    let mut silent = Vec::new();
    for entry in DEFAULT_STUN {
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
            "live_stun: {entry} {} (resolves {}, unresolved {}, requests {}, errors {}, \
             refused {}, ignored {})",
            answered(report.outcome),
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
            silent.push(entry);
        }
    }
    assert!(
        silent.is_empty(),
        "no global answer from {silent:?}: design §5.4 replaces such an entry with one of another operator"
    );
}
