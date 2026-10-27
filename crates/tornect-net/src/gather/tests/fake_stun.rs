//! Fake STUN servers on `127.0.0.1` with real sockets (design §12.2 "Fake
//! STUN server"): honest, lying, an error, silent, oversized, another
//! transaction ID, another port. The asking side is a [`LoopbackNet`]
//! machine, which admits loopback as if global, so its requests go out of
//! a real session socket and the replies come back through the
//! `PunchSocket` STUN tee and the codec. Real time: the counts are
//! checked, not the milliseconds.

use super::*;

use crate::mem::LoopbackNet;

/// A fake server on `127.0.0.1` answering as `answer` from its port, or
/// from a second port for [`Answer::OtherPort`].
struct LoopServer {
    addr: SocketAddr,
    heard: Ears,
    task: tokio::task::JoinHandle<()>,
}

impl LoopServer {
    async fn new(answer: Answer) -> Self {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("a server socket");
        let other = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("its other socket");
        let addr = socket.local_addr().expect("its address");
        let heard = Ears::default();
        let ears = Arc::clone(&heard);
        let task = tokio::spawn(async move {
            let mut buf = [0_u8; 2048];
            while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                lock(&ears).push(Heard {
                    at: Instant::now(),
                    from,
                    bytes: buf[..n].to_vec(),
                });
                if let Some(bytes) = reply(answer, &buf[..n], from) {
                    let out = if matches!(answer, Answer::OtherPort(_)) {
                        &other
                    } else {
                        &socket
                    };
                    let _ = out.send_to(&bytes, from).await;
                }
            }
        });
        Self { addr, heard, task }
    }

    fn heard(&self) -> Vec<Heard> {
        lock(&self.heard).clone()
    }
}

impl Drop for LoopServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// One asking machine at `127.0.0.x` and one server answering `answer`;
/// the report over `budget`, with or without the machine's host candidate.
async fn ask_loopback(
    x: u8,
    answer: Answer,
    with_hosts: bool,
    budget: Duration,
) -> (StunReport, Vec<Heard>, SocketAddr) {
    let env = LoopbackNet::new(x);
    let server = LoopServer::new(answer).await;
    let mut asker = Asker::new(&env).await;
    let me = SocketAddr::new(IpAddr::V4(env.ip()), asker.port());
    let hosts = if with_hosts { vec![me] } else { Vec::new() };
    let report = asker
        .ask_with(&env, &[server.addr.to_string()], &hosts, budget)
        .await;
    let heard = server.heard();
    assert!(
        heard.iter().all(|h| h.from == me),
        "from the session socket"
    );
    assert!(bare_requests(&heard).is_some() || heard.is_empty());
    assert_eq!(
        u64::from(report.stats.requests),
        asker.socket.counters().stun_sent
    );
    (report, heard, me)
}

/// An honest server behind a "NAT" (a fixed global answer) gives the srflx
/// after one request; one that reports the address it saw gives "no NAT"
/// when that is the host candidate, and the loopback srflx otherwise (only
/// a test environment admits it).
#[tokio::test]
async fn a_fake_server_on_loopback_answers_through_the_tee() {
    let (report, heard, _) = ask_loopback(2, Answer::Fixed(at(NAT)), true, GATHER_BUDGET).await;
    assert_eq!(report.outcome, srflx(NAT));
    assert_eq!((report.stats.requests, heard.len()), (1, 1));

    let (report, heard, _) = ask_loopback(3, Answer::Echo, true, GATHER_BUDGET).await;
    assert_eq!(report.outcome, StunOutcome::NoNat);
    assert_eq!(heard.len(), 1);

    let (report, _, me) = ask_loopback(4, Answer::Echo, false, GATHER_BUDGET).await;
    assert_eq!(report.outcome, srflx(&me.to_string()));
}

/// A lying server (a private mapped address) and an error response give
/// nothing, after one request each; a silent server is asked twice with one
/// transaction ID; an oversized answer, one under another transaction ID
/// and one from another port are never taken.
#[tokio::test]
async fn lying_failing_and_silent_fake_servers_give_nothing() {
    // One server, so the second send at 500 ms is the last; the budget
    // leaves it 500 ms of real time to leave and arrive.
    let short = ms(1000);
    let (report, heard, _) =
        ask_loopback(5, Answer::Fixed(at("192.168.0.1:3478")), true, short).await;
    assert_eq!(report.outcome, StunOutcome::Nothing);
    assert_eq!((report.stats.refused, heard.len()), (1, 1));

    let (report, heard, _) = ask_loopback(6, Answer::Error, true, short).await;
    assert_eq!(report.outcome, StunOutcome::Nothing);
    assert_eq!((report.stats.errors, heard.len()), (1, 1));

    for (x, answer) in [
        (7, Answer::Silent),
        (8, Answer::Oversized(at(NAT))),
        (9, Answer::OtherTxid(at(NAT))),
        (10, Answer::OtherPort(at(NAT))),
    ] {
        let (report, heard, _) = ask_loopback(x, answer, true, short).await;
        assert_eq!(report.outcome, StunOutcome::Nothing, "{answer:?}");
        assert_eq!(report.stats.requests, 2, "{answer:?}");
        assert_eq!(heard.len(), 2, "{answer:?}");
        let ignored = match answer {
            Answer::OtherTxid(_) | Answer::OtherPort(_) => 2,
            _ => 0,
        };
        assert_eq!(report.stats.ignored, ignored, "{answer:?}");
        // Real time: the retransmission leaves the RTO after the first
        // request (the exact schedule is checked on MemNet in paused time);
        // here it only has to be clearly later, since the server's reading
        // of either may lag on a loaded machine.
        assert!(heard[1].at - heard[0].at >= STUN_RTO / 2, "{answer:?}");
    }
}

/// The real machine's filter (no loopback) never sends to a loopback
/// server, whatever the list says: the entry is skipped and nothing is
/// sent.
#[tokio::test]
async fn without_the_test_override_a_loopback_server_is_never_asked() {
    let env = LoopbackNet::new(11);
    let server = LoopServer::new(Answer::Fixed(at(NAT))).await;
    let mut asker = Asker::new(&env).await;
    asker.filter.admit_loopback = false;
    let report = asker.ask(&env, &[server.addr.to_string()]).await;
    assert_eq!(report.outcome, StunOutcome::Nothing);
    assert_eq!((report.stats.requests, report.stats.unresolved), (0, 1));
    assert!(server.heard().is_empty());
}
