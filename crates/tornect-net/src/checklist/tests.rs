use super::*;

use std::collections::{HashMap, HashSet};

use proptest::prelude::*;

use crate::addr::Scope;
use crate::probe::Probe;

const TOKEN: [u8; 32] = [0x33; 32];

const OWN_V4: &str = "192.168.1.10";
const OWN_ULA: &str = "fd12:3456:789a:1::10";
const OWN_GLOBAL_V6: &str = "2a01:4f8:1:2::10";

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn addr(text: &str) -> SocketAddr {
    text.parse().expect("a socket address")
}

fn ip(text: &str) -> IpAddr {
    text.parse().expect("an IP address")
}

fn other(role: TornectRole) -> TornectRole {
    match role {
        TornectRole::Viewer => TornectRole::Host,
        TornectRole::Host => TornectRole::Viewer,
    }
}

/// The IPv6 addresses this side offered.
fn offered() -> V6Sources {
    V6Sources {
        global: Some(OWN_GLOBAL_V6.parse().expect("an IPv6 address")),
        ula: Some(OWN_ULA.parse().expect("an IPv6 address")),
    }
}

/// A side at `own` on 192.168.1.0/24 with the ULA /48 `fd12:3456:789a::/48`
/// and, in internet scope, a global IPv6 offered.
fn filter_at(own: &str, scope: Scope) -> RemoteFilter {
    RemoteFilter {
        scope,
        on_link: vec!["192.168.1.0/24".parse().expect("a prefix")],
        own_ula48: Some("fd12:3456:789a::/48".parse().expect("a prefix")),
        local_nets: vec![
            "192.168.1.0/24".parse().expect("a prefix"),
            "fd12:3456:789a:1::/64".parse().expect("a prefix"),
        ],
        have_v4: true,
        have_v6: scope == Scope::Internet,
        dual_stack: true,
        global_families: (true, true),
        own: vec![ip(own), ip(OWN_ULA), ip(OWN_GLOBAL_V6)],
        admit_loopback: false,
    }
}

fn filter(scope: Scope) -> RemoteFilter {
    filter_at(OWN_V4, scope)
}

fn checklist(punch: PunchRole, me: TornectRole, scope: Scope) -> (Checklist, ProbeGate) {
    let gate = ProbeGate::new();
    let list = Checklist::new(
        punch,
        me,
        ProbeKey::derive(&TOKEN),
        filter(scope),
        gate.clone(),
        offered(),
    );
    (list, gate)
}

fn cand(kind: CandidateKind, a: &str) -> Candidate {
    Candidate {
        kind,
        addr: addr(a),
    }
}

fn host(a: &str) -> Candidate {
    cand(CandidateKind::Host, a)
}

/// The other side of the session: the same key, the other role.
struct Peer {
    key: ProbeKey,
    role: TornectRole,
}

impl Peer {
    fn of(me: TornectRole) -> Self {
        Self {
            key: ProbeKey::derive(&TOKEN),
            role: other(me),
        }
    }

    fn request(&self) -> (Txid, [u8; PROBE_LEN]) {
        self.key.request(self.role).expect("OS randomness")
    }

    fn request_with(&self, txid: &Txid) -> [u8; PROBE_LEN] {
        self.key.seal(false, self.role, txid, &[7; 12])
    }

    fn response(&self, txid: &Txid) -> [u8; PROBE_LEN] {
        self.key.response(self.role, txid).expect("OS randomness")
    }

    /// A probe the checklist sent, as the peer reads it.
    fn read(&self, bytes: &[u8]) -> Probe {
        self.key
            .decode(self.role, bytes)
            .expect("a probe for the peer")
    }
}

type Sent = (SocketAddr, Option<IpAddr>, [u8; PROBE_LEN]);

fn sends(actions: &[Action]) -> Vec<Sent> {
    actions
        .iter()
        .filter_map(|a| match *a {
            Action::Send { to, src, bytes } => Some((to, src, bytes)),
            _ => None,
        })
        .collect()
}

fn in_flight(list: &Checklist) -> usize {
    list.targets.iter().filter(|t| t.in_flight()).count()
}

/// Polls `list` at `from` and then at every wakeup up to `until`; every
/// action with its time. Checks the in-flight cap after every poll and that
/// every wakeup makes progress.
fn drive(list: &mut Checklist, from: Instant, until: Instant) -> Vec<(Instant, Action)> {
    let mut log: Vec<(Instant, Action)> = list.poll(from).into_iter().map(|a| (from, a)).collect();
    let mut now = from;
    let mut idle = 0;
    while let Some(next) = list.next_wakeup() {
        if next > until {
            break;
        }
        now = now.max(next);
        let actions = list.poll(now);
        assert!(in_flight(list) <= MAX_IN_FLIGHT);
        if actions.is_empty() && list.next_wakeup() == Some(next) {
            idle += 1;
            assert!(idle < 3, "a wakeup that makes no progress");
        } else {
            idle = 0;
        }
        log.extend(actions.into_iter().map(|a| (now, a)));
    }
    log
}

fn send_times(log: &[(Instant, Action)], to: SocketAddr, t0: Instant) -> Vec<Duration> {
    log.iter()
        .filter(|(_, a)| matches!(a, Action::Send { to: dest, .. } if *dest == to))
        .map(|(at, _)| *at - t0)
        .collect()
}

#[test]
fn the_lower_device_key_controls_and_equal_keys_never_punch() {
    let low = [1; 32];
    let mut high = [1; 32];
    high[31] = 2;
    assert_eq!(PunchRole::of(&low, &high), Some(PunchRole::Controlling));
    assert_eq!(PunchRole::of(&high, &low), Some(PunchRole::Controlled));
    assert_eq!(PunchRole::of(&low, &low), None);
}

#[test]
fn the_budget_constants_are_the_designs() {
    assert_eq!(TA, ms(20));
    assert_eq!(MAX_IN_FLIGHT, 8);
    assert_eq!(MAX_TARGETS, ProbeGate::CAPACITY);
    assert_eq!(MAX_TARGETS, 20);
    assert_eq!(MAX_UNVALIDATED_BYTES, 480);
    assert_eq!(MAX_PROBE_BYTES, 5760);
    assert_eq!(SAME_SITE_SCHEDULE.sends, [ms(0), ms(200), ms(400), ms(800)]);
    assert_eq!(SAME_SITE_SCHEDULE.fail, ms(1200));
    assert_eq!(
        INTERNET_SCHEDULE.sends,
        [ms(0), ms(500), ms(1000), ms(2000)]
    );
    assert_eq!(INTERNET_SCHEDULE.fail, ms(3000));
}

/// A same-site target gets requests at exactly 0, 200, 400 and 800 ms
/// after it starts, each with a fresh txid, and fails at 1200 ms; with both
/// sides done, that failure is the checklist's.
#[test]
fn a_same_site_target_follows_its_schedule_exactly() {
    let t0 = Instant::now();
    let (mut list, gate) = checklist(PunchRole::Controlled, TornectRole::Viewer, Scope::SameSite);
    let peer = Peer::of(TornectRole::Viewer);
    let a = addr("192.168.1.20:50000");
    list.add_remote(host("192.168.1.20:50000"));
    list.remote_done();
    list.local_done();
    let log = drive(&mut list, t0, t0 + ms(5000));
    assert_eq!(send_times(&log, a, t0), [ms(0), ms(200), ms(400), ms(800)]);
    let txids: HashSet<Txid> = log
        .iter()
        .filter_map(|(_, act)| match act {
            Action::Send { bytes, src, .. } => {
                assert_eq!(*src, None);
                let probe = peer.read(bytes);
                assert!(!probe.response);
                assert_eq!(probe.sender, TornectRole::Viewer);
                Some(probe.txid)
            }
            _ => None,
        })
        .collect();
    assert_eq!(txids.len(), 4);
    let failed: Vec<Duration> = log
        .iter()
        .filter(|(_, act)| *act == Action::Failed)
        .map(|(at, _)| *at - t0)
        .collect();
    assert_eq!(failed, [ms(1200)]);
    let stats = list.stats();
    assert_eq!((stats.requests_sent, stats.failed_targets), (4, 1));
    assert!(gate.is_empty());
    assert!(list.validated().is_empty());
}

/// A target that is not on our site gets the internet schedule: 0, 500,
/// 1000 and 2000 ms, failure at 3000 ms.
#[test]
fn an_internet_target_follows_the_internet_schedule() {
    let t0 = Instant::now();
    let (mut list, _) = checklist(PunchRole::Controlled, TornectRole::Host, Scope::Internet);
    let a = addr("93.184.216.34:50000");
    list.add_remote(host("93.184.216.34:50000"));
    list.remote_done();
    list.local_done();
    let log = drive(&mut list, t0, t0 + ms(10_000));
    assert_eq!(
        send_times(&log, a, t0),
        [ms(0), ms(500), ms(1000), ms(2000)]
    );
    let failed: Vec<Duration> = log
        .iter()
        .filter(|(_, act)| *act == Action::Failed)
        .map(|(at, _)| *at - t0)
        .collect();
    assert_eq!(failed, [ms(3000)]);
}

/// A late poll sends one request for the slots it missed and keeps the
/// later slots at their times.
#[test]
fn a_late_poll_does_not_burst() {
    let t0 = Instant::now();
    let (mut list, _) = checklist(PunchRole::Controlled, TornectRole::Viewer, Scope::SameSite);
    list.add_remote(host("192.168.1.20:50000"));
    assert_eq!(sends(&list.poll(t0)).len(), 1);
    assert_eq!(sends(&list.poll(t0 + ms(450))).len(), 1);
    assert_eq!(list.next_wakeup(), Some(t0 + ms(800)));
    assert_eq!(sends(&list.poll(t0 + ms(800))).len(), 1);
    assert_eq!(list.stats().requests_sent, 3);
}

/// Targets start at least TA apart, at most eight are in flight, and the
/// ninth starts when the first one's last request has gone out.
#[test]
fn starts_are_paced_and_at_most_eight_are_in_flight() {
    let t0 = Instant::now();
    let (mut list, _) = checklist(PunchRole::Controlled, TornectRole::Viewer, Scope::SameSite);
    let targets: Vec<SocketAddr> = (20..32)
        .map(|n| addr(&format!("192.168.1.{n}:50000")))
        .collect();
    for a in &targets {
        list.add_remote(Candidate {
            kind: CandidateKind::Host,
            addr: *a,
        });
    }
    let log = drive(&mut list, t0, t0 + ms(5000));
    let starts: Vec<Duration> = targets
        .iter()
        .map(|a| send_times(&log, *a, t0)[0])
        .collect();
    assert_eq!(
        starts,
        [0, 20, 40, 60, 80, 100, 120, 140, 800, 820, 840, 860].map(ms)
    );
    for a in &targets {
        let times = send_times(&log, *a, t0);
        let start = times[0];
        assert_eq!(times, SAME_SITE_SCHEDULE.sends.map(|offset| start + offset));
    }
}

/// A target is validated only by a response carrying the txid of a request
/// of ours, from exactly the address that request went to, and only once;
/// it then enters the gate, and its requests stop.
#[test]
fn a_response_validates_only_its_own_round_trip() {
    let t0 = Instant::now();
    let (mut list, gate) = checklist(PunchRole::Controlled, TornectRole::Viewer, Scope::SameSite);
    let peer = Peer::of(TornectRole::Viewer);
    let a = addr("192.168.1.20:50000");
    let b = addr("192.168.1.21:50000");
    list.add_remote(host("192.168.1.20:50000"));
    list.add_remote(host("192.168.1.21:50000"));
    let first = sends(&list.poll(t0));
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].0, a);
    let txid = peer.read(&first[0].2).txid;

    let never_sent = peer.response(&[9; 12]);
    assert!(
        list.on_datagram(a, None, &never_sent, t0 + ms(5))
            .is_empty()
    );
    assert!(!list.is_validated(a));

    let wrong_source = peer.response(&txid);
    assert!(
        list.on_datagram(b, None, &wrong_source, t0 + ms(6))
            .is_empty()
    );
    assert!(!list.is_validated(a) && !list.is_validated(b));
    assert_eq!(list.stats().unexpected_responses, 2);

    let mapped = addr("[::ffff:192.168.1.20]:50000");
    let right = peer.response(&txid);
    assert!(
        list.on_datagram(mapped, None, &right, t0 + ms(10))
            .is_empty()
    );
    assert!(list.is_validated(a));
    assert!(list.is_validated(mapped));
    assert!(gate.admits(a));
    assert_eq!(gate.len(), 1);
    assert_eq!(list.validated(), [a]);

    assert!(list.on_datagram(a, None, &right, t0 + ms(11)).is_empty());
    let stats = list.stats();
    assert_eq!((stats.validated, stats.unexpected_responses), (1, 3));

    let log = drive(&mut list, t0 + ms(11), t0 + ms(3000));
    assert!(send_times(&log, a, t0).is_empty());
    assert_eq!(send_times(&log, b, t0).len(), 4);
    assert_eq!(gate.len(), 1);
}

/// A response that arrives after its target failed (1200 ms on the same
/// site) validates nothing: its txid expired with the target.
#[test]
fn a_late_response_validates_nothing() {
    let t0 = Instant::now();
    let (mut list, gate) = checklist(PunchRole::Controlled, TornectRole::Host, Scope::SameSite);
    let peer = Peer::of(TornectRole::Host);
    let a = addr("192.168.1.20:50000");
    list.add_remote(host("192.168.1.20:50000"));
    let first = sends(&list.poll(t0));
    let txid = peer.read(&first[0].2).txid;
    list.on_datagram(a, None, &peer.response(&txid), t0 + ms(1200));
    assert!(!list.is_validated(a));
    assert!(gate.is_empty());
    assert_eq!(list.stats().unexpected_responses, 1);
}

/// The ranks of design §7.6: same site first, then a global IPv6 host,
/// a public IPv4 host, a mapping, a reflexive address, any other private
/// address; two sites with the same private range are demoted, and a
/// private address behind the same public IPv4 is promoted and same-site.
#[test]
fn ranks_follow_the_design_table() {
    let (mut list, _) = checklist(PunchRole::Controlling, TornectRole::Viewer, Scope::Internet);
    let on_link = addr("192.168.1.20:50000");
    let off_link = addr("10.1.2.3:50000");
    let ula_here = addr("[fd12:3456:789a:2::5]:50000");
    let ula_elsewhere = addr("[fd99:1::5]:50000");
    let table = [
        (on_link, CandidateKind::Host, Rank::SameSite),
        (on_link, CandidateKind::Prflx, Rank::SameSite),
        (ula_here, CandidateKind::Host, Rank::SameSite),
        (
            addr("[2a01:4f8:9:9::5]:50000"),
            CandidateKind::Host,
            Rank::GlobalV6Host,
        ),
        (
            addr("93.184.216.34:50000"),
            CandidateKind::Host,
            Rank::PublicV4Host,
        ),
        (
            addr("93.184.216.35:40000"),
            CandidateKind::Mapped,
            Rank::Mapped,
        ),
        (
            addr("93.184.216.36:40001"),
            CandidateKind::Srflx,
            Rank::Reflexive,
        ),
        (
            addr("93.184.216.37:40002"),
            CandidateKind::Prflx,
            Rank::Reflexive,
        ),
        (off_link, CandidateKind::Prflx, Rank::Reflexive),
        (off_link, CandidateKind::Host, Rank::OtherPrivate),
        (ula_elsewhere, CandidateKind::Host, Rank::OtherPrivate),
    ];
    for (a, kind, rank) in table {
        assert_eq!(list.rank(a, kind), rank, "{kind:?} {}", Redacted(&a));
    }
    assert!(list.same_site(on_link));
    assert!(list.same_site(ula_here));
    assert!(!list.same_site(off_link));

    // The peer's public addresses come from its signalled candidates.
    list.add_remote(cand(CandidateKind::Srflx, "93.184.216.36:40001"));
    list.add_remote(host("10.1.2.3:50000"));

    // Our public address differs from the peer's: the same private range
    // on two sites.
    list.set_local_public(&[ip("93.184.216.99")]);
    assert_eq!(list.rank(on_link, CandidateKind::Host), Rank::OtherPrivate);
    assert!(!list.same_site(on_link));
    assert_eq!(list.rank(off_link, CandidateKind::Host), Rank::OtherPrivate);

    // The same public address: the same NAT.
    list.set_local_public(&[ip("93.184.216.36"), ip("192.168.1.1")]);
    assert_eq!(list.rank(on_link, CandidateKind::Host), Rank::SameSite);
    assert!(list.same_site(on_link));
    assert_eq!(list.rank(off_link, CandidateKind::Host), Rank::PublicV4Host);
    assert!(list.same_site(off_link));
    assert_eq!(
        list.rank(addr("93.184.216.36:40001"), CandidateKind::Srflx),
        Rank::Reflexive
    );
}

/// The best-ranked waiting target starts first; a same-site target and a
/// private address behind our NAT follow the same-site schedule, every
/// other the internet one.
#[test]
fn the_best_ranked_target_starts_first_on_its_schedule() {
    let t0 = Instant::now();
    let (mut list, _) = checklist(PunchRole::Controlled, TornectRole::Host, Scope::Internet);
    let order = [
        cand(CandidateKind::Srflx, "93.184.216.36:40001"),
        host("10.1.2.3:50000"),
        cand(CandidateKind::Mapped, "93.184.216.35:40000"),
        host("93.184.216.34:50000"),
        host("[2a01:4f8:9:9::5]:50000"),
        host("192.168.1.20:50000"),
    ];
    for c in order {
        list.add_remote(c);
    }
    let log = drive(&mut list, t0, t0 + ms(10_000));
    let start = |a: &str| send_times(&log, addr(a), t0)[0];
    assert_eq!(start("192.168.1.20:50000"), ms(0));
    assert_eq!(start("[2a01:4f8:9:9::5]:50000"), ms(20));
    assert_eq!(start("93.184.216.34:50000"), ms(40));
    assert_eq!(start("93.184.216.35:40000"), ms(60));
    assert_eq!(start("93.184.216.36:40001"), ms(80));
    assert_eq!(start("10.1.2.3:50000"), ms(100));
    assert_eq!(
        send_times(&log, addr("192.168.1.20:50000"), t0),
        SAME_SITE_SCHEDULE.sends
    );
    assert_eq!(
        send_times(&log, addr("93.184.216.34:50000"), t0),
        INTERNET_SCHEDULE.sends.map(|d| d + ms(40))
    );

    // Behind the same NAT, a private address checks on the same-site
    // schedule.
    let (mut list, _) = checklist(PunchRole::Controlled, TornectRole::Host, Scope::Internet);
    list.set_local_public(&[ip("93.184.216.36")]);
    list.add_remote(cand(CandidateKind::Srflx, "93.184.216.36:40001"));
    list.add_remote(host("10.1.2.3:50000"));
    let log = drive(&mut list, t0, t0 + ms(10_000));
    assert_eq!(
        send_times(&log, addr("10.1.2.3:50000"), t0),
        SAME_SITE_SCHEDULE.sends
    );
    assert_eq!(
        send_times(&log, addr("93.184.216.36:40001"), t0),
        INTERNET_SCHEDULE.sends.map(|d| d + ms(20))
    );
}

/// Only candidates the remote filter admits become targets, a peer never
/// signals a peer-reflexive kind, at most sixteen are kept, and a repeated
/// address is kept once.
#[test]
fn the_remote_filter_decides_which_candidates_become_targets() {
    let t0 = Instant::now();
    let (mut list, _) = checklist(PunchRole::Controlled, TornectRole::Viewer, Scope::SameSite);
    for refused in [
        host("10.1.2.3:50000"),
        host("93.184.216.34:50000"),
        host("192.168.1.20:1023"),
        host("192.168.1.20:1900"),
        host("192.168.1.10:50000"),
        host("192.168.1.255:50000"),
        host("127.0.0.1:50000"),
        host("[fe80::1]:50000"),
        host("[fd99:1::5]:50000"),
        cand(CandidateKind::Prflx, "192.168.1.20:50000"),
    ] {
        list.add_remote(refused);
    }
    assert_eq!(list.stats().candidates_refused, 10);
    assert!(list.targets.is_empty());
    for n in 20..40 {
        list.add_remote(host(&format!("192.168.1.{n}:50000")));
    }
    list.add_remote(host("192.168.1.20:50000"));
    let stats = list.stats();
    assert_eq!(list.targets.len(), MAX_REMOTE_CANDIDATES);
    assert_eq!(stats.candidates_dropped, 4);
    assert_eq!(
        stats.candidates_duplicate, 1,
        "a kept address, past the cap"
    );
    let (mut list, _) = checklist(PunchRole::Controlled, TornectRole::Viewer, Scope::SameSite);
    list.add_remote(host("192.168.1.20:50000"));
    list.add_remote(host("[::ffff:192.168.1.20]:50000"));
    assert_eq!(list.targets.len(), 1);
    assert_eq!(list.stats().candidates_duplicate, 1);
    let log = drive(&mut list, t0, t0 + ms(2000));
    assert!(log.iter().all(|(_, act)| match act {
        Action::Send { to, .. } => *to == addr("192.168.1.20:50000"),
        _ => true,
    }));
}

/// An answered request from an unknown source teaches its address and
/// draws exactly one triggered check, which is never retransmitted on a
/// timer; its response validates the address.
#[test]
fn an_unknown_source_is_learned_and_draws_one_triggered_check() {
    let t0 = Instant::now();
    let (mut list, gate) = checklist(PunchRole::Controlled, TornectRole::Viewer, Scope::SameSite);
    let peer = Peer::of(TornectRole::Viewer);
    let p = addr("192.168.1.30:50000");
    let (txid, request) = peer.request();
    let out = sends(&list.on_datagram(p, Some(ip(OWN_V4)), &request, t0));
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].0, p);
    assert_eq!(out[0].1, None);
    assert_eq!(
        peer.read(&out[0].2),
        Probe {
            response: true,
            sender: TornectRole::Viewer,
            txid
        }
    );
    assert_eq!(out[1].0, p);
    let check = peer.read(&out[1].2);
    assert!(!check.response);
    assert_eq!(list.kind_of(p), Some(CandidateKind::Prflx));
    let stats = list.stats();
    assert_eq!(
        (
            stats.prflx_learned,
            stats.triggered_sent,
            stats.requests_sent
        ),
        (1, 1, 1)
    );
    assert!(list.heard_from_peer());

    let log = drive(&mut list, t0, t0 + ms(5000));
    assert!(send_times(&log, p, t0).is_empty(), "no timer resends");

    let (mut list, gate2) = checklist(PunchRole::Controlled, TornectRole::Viewer, Scope::SameSite);
    let out = sends(&list.on_datagram(p, Some(ip(OWN_V4)), &request, t0));
    let check = peer.read(&out[1].2);
    list.on_datagram(p, None, &peer.response(&check.txid), t0 + ms(3));
    assert!(list.is_validated(p));
    assert!(gate2.admits(p));
    assert!(gate.is_empty());
}

/// Each answered request from a learned address draws at most one
/// triggered check, and the address gets at most four.
#[test]
fn triggered_checks_are_one_per_request_and_four_per_address() {
    let t0 = Instant::now();
    let (mut list, _) = checklist(PunchRole::Controlled, TornectRole::Host, Scope::SameSite);
    let peer = Peer::of(TornectRole::Host);
    let p = addr("192.168.1.30:50000");
    let mut requests = 0;
    let mut responses = 0;
    for k in 0..7u64 {
        let (_, request) = peer.request();
        let out = sends(&list.on_datagram(p, None, &request, t0 + ms(k)));
        assert!(out.len() <= 2);
        for (_, _, bytes) in out {
            if peer.read(&bytes).response {
                responses += 1;
            } else {
                requests += 1;
            }
        }
    }
    assert_eq!((responses, requests), (7, MAX_REQUESTS_PER_TARGET));
    assert_eq!(list.stats().triggered_sent, 4);
}

/// At most four addresses are learned; a fifth unknown source is answered
/// but neither learned nor checked.
#[test]
fn at_most_four_addresses_are_learned() {
    let t0 = Instant::now();
    let (mut list, _) = checklist(PunchRole::Controlled, TornectRole::Viewer, Scope::SameSite);
    let peer = Peer::of(TornectRole::Viewer);
    for n in 30..35 {
        let (_, request) = peer.request();
        let from = addr(&format!("192.168.1.{n}:50000"));
        let out = sends(&list.on_datagram(from, None, &request, t0));
        let expected = if n < 34 { 2 } else { 1 };
        assert_eq!(out.len(), expected, "source {n}");
    }
    let stats = list.stats();
    assert_eq!(
        (
            stats.prflx_learned,
            stats.prflx_dropped,
            stats.responses_sent
        ),
        (4, 1, 5)
    );
    assert_eq!(list.targets.len(), MAX_PRFLX);
}

/// A learned address the peer later signals takes the signalled kind and
/// the schedule, within the same four requests; a validated one keeps its
/// round trip and reads as the signalled kind (`PATH host`).
#[test]
fn a_learned_address_the_peer_signals_takes_its_kind() {
    let t0 = Instant::now();
    let (mut list, _) = checklist(PunchRole::Controlled, TornectRole::Viewer, Scope::SameSite);
    let peer = Peer::of(TornectRole::Viewer);
    let p = addr("192.168.1.30:50000");
    let (_, request) = peer.request();
    assert_eq!(list.on_datagram(p, None, &request, t0).len(), 2);
    list.add_remote(host("192.168.1.30:50000"));
    assert_eq!(list.kind_of(p), Some(CandidateKind::Host));
    let log = drive(&mut list, t0 + ms(1), t0 + ms(5000));
    assert_eq!(send_times(&log, p, t0), [ms(1), ms(201), ms(401)]);
    assert_eq!(list.stats().requests_sent, 4);
    assert_eq!(list.stats().candidates_duplicate, 0);

    let (mut list, _) = checklist(PunchRole::Controlling, TornectRole::Viewer, Scope::SameSite);
    let out = sends(&list.on_datagram(p, None, &request, t0));
    let check = peer.read(&out[1].2);
    list.on_datagram(p, None, &peer.response(&check.txid), t0 + ms(2));
    let log = drive(&mut list, t0 + ms(2), t0 + ms(400));
    assert!(log.contains(&(t0 + ms(102), Action::Nominate(p))));
    assert_eq!(list.winner_kind(), Some(CandidateKind::Prflx));
    list.add_remote(host("192.168.1.30:50000"));
    assert_eq!(list.winner_kind(), Some(CandidateKind::Host));
    assert!(list.is_validated(p));
}

/// The nomination comes `clamp(1.5 × rtt, 100 ms, 600 ms)` after the first
/// validated round trip, once, and only on the controlling side.
#[test]
fn the_nomination_waits_for_the_measured_grace() {
    assert_eq!(nomination_grace(ms(10)), ms(100));
    assert_eq!(nomination_grace(ms(200)), ms(300));
    assert_eq!(nomination_grace(ms(2000)), ms(600));
    for (rtt, grace) in [(ms(30), ms(100)), (ms(250), ms(375)), (ms(900), ms(600))] {
        for punch in [PunchRole::Controlling, PunchRole::Controlled] {
            let t0 = Instant::now();
            let (mut list, _) = checklist(punch, TornectRole::Viewer, Scope::SameSite);
            let peer = Peer::of(TornectRole::Viewer);
            let a = addr("192.168.1.20:50000");
            list.add_remote(host("192.168.1.20:50000"));
            let first = sends(&list.poll(t0));
            let txid = peer.read(&first[0].2).txid;
            list.on_datagram(a, None, &peer.response(&txid), t0 + rtt);
            let log = drive(&mut list, t0 + rtt, t0 + ms(5000));
            let nominations: Vec<(Instant, Action)> = log
                .into_iter()
                .filter(|(_, act)| matches!(act, Action::Nominate(_)))
                .collect();
            if punch == PunchRole::Controlling {
                assert_eq!(nominations, [(t0 + rtt + grace, Action::Nominate(a))]);
                assert_eq!(list.nominated(), Some(a));
                assert_eq!(list.winner_kind(), Some(CandidateKind::Host));
            } else {
                assert!(nominations.is_empty());
                assert_eq!(list.nominated(), None);
            }
        }
    }
}

/// The nomination takes the best-ranked validated address, not the first.
#[test]
fn the_nomination_takes_the_best_ranked_validated_address() {
    let t0 = Instant::now();
    let (mut list, _) = checklist(PunchRole::Controlling, TornectRole::Host, Scope::Internet);
    let peer = Peer::of(TornectRole::Host);
    let srflx = addr("93.184.216.36:40001");
    let lan = addr("192.168.1.20:50000");
    list.add_remote(cand(CandidateKind::Srflx, "93.184.216.36:40001"));
    let first = sends(&list.poll(t0));
    list.on_datagram(
        srflx,
        None,
        &peer.response(&peer.read(&first[0].2).txid),
        t0 + ms(40),
    );
    list.add_remote(host("192.168.1.20:50000"));
    let next = sends(&list.poll(t0 + ms(50)));
    assert_eq!(next[0].0, lan);
    list.on_datagram(
        lan,
        None,
        &peer.response(&peer.read(&next[0].2).txid),
        t0 + ms(52),
    );
    let log = drive(&mut list, t0 + ms(52), t0 + ms(1000));
    let nominations: Vec<Action> = log
        .into_iter()
        .filter_map(|(at, act)| matches!(act, Action::Nominate(_)).then_some((at, act)))
        .map(|(at, act)| {
            assert_eq!(at, t0 + ms(140));
            act
        })
        .collect();
    assert_eq!(nominations, [Action::Nominate(lan)]);
}

/// After the nomination no new target starts.
#[test]
fn no_target_starts_after_the_nomination() {
    let t0 = Instant::now();
    let (mut list, _) = checklist(PunchRole::Controlling, TornectRole::Viewer, Scope::SameSite);
    let peer = Peer::of(TornectRole::Viewer);
    let a = addr("192.168.1.20:50000");
    list.add_remote(host("192.168.1.20:50000"));
    let first = sends(&list.poll(t0));
    list.on_datagram(
        a,
        None,
        &peer.response(&peer.read(&first[0].2).txid),
        t0 + ms(2),
    );
    let log = drive(&mut list, t0 + ms(2), t0 + ms(102));
    assert!(log.contains(&(t0 + ms(102), Action::Nominate(a))));
    list.add_remote(host("192.168.1.21:50000"));
    let log = drive(&mut list, t0 + ms(103), t0 + ms(5000));
    assert!(log.is_empty());
    assert_eq!(list.next_wakeup(), None);
}

/// The early failure needs the peer's candidates done, this side's
/// gathering done and every target failed; it comes once.
#[test]
fn the_early_failure_waits_for_both_sides_and_comes_once() {
    let t0 = Instant::now();
    let (mut list, _) = checklist(PunchRole::Controlled, TornectRole::Viewer, Scope::SameSite);
    list.add_remote(host("192.168.1.20:50000"));
    let log = drive(&mut list, t0, t0 + ms(5000));
    assert!(!log.iter().any(|(_, act)| *act == Action::Failed));
    list.remote_done();
    assert!(!list.poll(t0 + ms(5000)).contains(&Action::Failed));
    list.local_done();
    assert_eq!(list.poll(t0 + ms(5001)), [Action::Failed]);
    assert!(list.poll(t0 + ms(5002)).is_empty());

    // Nothing to check at all: the failure comes at once.
    let (mut list, _) = checklist(PunchRole::Controlled, TornectRole::Viewer, Scope::SameSite);
    list.local_done();
    list.remote_done();
    assert_eq!(list.poll(t0), [Action::Failed]);

    // A validated target is never a failure.
    let (mut list, _) = checklist(PunchRole::Controlled, TornectRole::Viewer, Scope::SameSite);
    let peer = Peer::of(TornectRole::Viewer);
    let a = addr("192.168.1.20:50000");
    list.add_remote(host("192.168.1.20:50000"));
    list.add_remote(host("192.168.1.21:50000"));
    list.local_done();
    list.remote_done();
    let first = sends(&list.poll(t0));
    list.on_datagram(
        a,
        None,
        &peer.response(&peer.read(&first[0].2).txid),
        t0 + ms(2),
    );
    let log = drive(&mut list, t0 + ms(2), t0 + ms(5000));
    assert!(!log.iter().any(|(_, act)| *act == Action::Failed));
}

/// `Failed` is advice to the caller (design §7.6: its deadline handles
/// the rest): the checklist goes on answering, learning and validating, and
/// the controlling side still nominates what validates afterwards.
#[test]
fn a_failure_is_advice_and_a_later_round_trip_still_counts() {
    let t0 = Instant::now();
    let (mut list, gate) = checklist(PunchRole::Controlling, TornectRole::Viewer, Scope::SameSite);
    let peer = Peer::of(TornectRole::Viewer);
    list.local_done();
    list.remote_done();
    assert_eq!(list.poll(t0), [Action::Failed]);
    let a = addr("192.168.1.30:50000");
    let (_, request) = peer.request();
    let out = sends(&list.on_datagram(a, None, &request, t0 + ms(100)));
    assert_eq!(out.len(), 2, "a response and a triggered check");
    let check = peer.read(&out[1].2);
    assert!(!check.response);
    list.on_datagram(a, None, &peer.response(&check.txid), t0 + ms(102));
    assert!(list.is_validated(a));
    assert!(gate.admits(a));
    let log = drive(&mut list, t0 + ms(102), t0 + ms(1000));
    let acts: Vec<Action> = log.into_iter().map(|(_, act)| act).collect();
    assert_eq!(acts, [Action::Nominate(a)], "no second failure");
}

/// A learned address with a triggered check still outstanding holds the
/// failure back until that check expires.
#[test]
fn an_outstanding_triggered_check_holds_the_failure_back() {
    let t0 = Instant::now();
    let (mut list, _) = checklist(PunchRole::Controlled, TornectRole::Viewer, Scope::SameSite);
    let peer = Peer::of(TornectRole::Viewer);
    list.local_done();
    list.remote_done();
    let (_, request) = peer.request();
    let out = list.on_datagram(addr("192.168.1.30:50000"), None, &request, t0);
    assert_eq!(out.len(), 2);
    let log = drive(&mut list, t0, t0 + ms(5000));
    let failed: Vec<Instant> = log
        .iter()
        .filter(|(_, act)| *act == Action::Failed)
        .map(|(at, _)| *at)
        .collect();
    assert_eq!(failed, [t0 + SAME_SITE_SCHEDULE.fail]);
}

/// Tag checks are limited to 200 a second, refilled at one every 5 ms;
/// datagrams that are not probe-shaped cost no check.
#[test]
fn tag_checks_are_limited_to_two_hundred_a_second() {
    let t0 = Instant::now();
    let (mut list, _) = checklist(PunchRole::Controlled, TornectRole::Viewer, Scope::SameSite);
    let stranger = ProbeKey::derive(&[0x44; 32]);
    let from = addr("192.168.1.20:50000");
    let (_, forged) = stranger.request(TornectRole::Host).expect("OS randomness");
    let mut short = forged;
    short[0] = 0x40;
    for _ in 0..300 {
        list.on_datagram(from, None, &short, t0);
    }
    for _ in 0..250 {
        list.on_datagram(from, None, &forged, t0);
    }
    let stats = list.stats();
    assert_eq!(
        (stats.malformed, stats.bad_tag, stats.rate_limited),
        (300, 200, 50)
    );
    list.on_datagram(from, None, &forged, t0 + ms(4));
    assert_eq!(list.stats().rate_limited, 51);
    list.on_datagram(from, None, &forged, t0 + ms(5));
    list.on_datagram(from, None, &forged, t0 + ms(5));
    assert_eq!((list.stats().bad_tag, list.stats().rate_limited), (201, 52));
    for _ in 0..250 {
        list.on_datagram(from, None, &forged, t0 + ms(2000));
    }
    assert_eq!(
        (list.stats().bad_tag, list.stats().rate_limited),
        (401, 102)
    );
    assert!(!list.heard_from_peer());
}

/// At most eight responses go to one source and 64 in a session.
#[test]
fn responses_are_capped_per_source_and_per_session() {
    let t0 = Instant::now();
    let (mut list, _) = checklist(PunchRole::Controlled, TornectRole::Host, Scope::SameSite);
    let peer = Peer::of(TornectRole::Host);
    let mut answered = 0;
    for n in 20..32 {
        let from = addr(&format!("192.168.1.{n}:50000"));
        for _ in 0..10 {
            let (txid, request) = peer.request();
            for (to, _, bytes) in sends(&list.on_datagram(from, None, &request, t0)) {
                let probe = peer.read(&bytes);
                if probe.response {
                    assert_eq!((to, probe.txid), (from, txid));
                    answered += 1;
                }
            }
        }
    }
    assert_eq!(answered, MAX_RESPONSES);
    let stats = list.stats();
    assert_eq!(stats.responses_sent, 64);
    assert_eq!(stats.responses_capped, 120 - 64);
    for (addr, count) in &list.answered_to {
        assert!(*count <= MAX_RESPONSES_PER_SOURCE, "{}", Redacted(addr));
    }
}

/// A request's txid is answered once: a replay, from the same or another
/// source, is dropped.
#[test]
fn a_replayed_request_is_never_answered_twice() {
    let t0 = Instant::now();
    let (mut list, _) = checklist(PunchRole::Controlled, TornectRole::Viewer, Scope::SameSite);
    let peer = Peer::of(TornectRole::Viewer);
    let (txid, request) = peer.request();
    let a = addr("192.168.1.20:50000");
    assert_eq!(list.on_datagram(a, None, &request, t0).len(), 2);
    assert!(list.on_datagram(a, None, &request, t0 + ms(1)).is_empty());
    let again = peer.request_with(&txid);
    let b = addr("192.168.1.21:50000");
    assert!(list.on_datagram(b, None, &again, t0 + ms(2)).is_empty());
    assert_eq!(list.stats().replayed, 2);
    assert_eq!(list.stats().responses_sent, 1);
}

/// A request from a source the remote filter refuses is never answered
/// and teaches nothing, though it proves the peer was heard.
#[test]
fn requests_from_refused_sources_are_never_answered() {
    let t0 = Instant::now();
    let (mut list, gate) = checklist(PunchRole::Controlled, TornectRole::Viewer, Scope::SameSite);
    let peer = Peer::of(TornectRole::Viewer);
    let refused = [
        "10.1.2.3:50000",
        "93.184.216.34:50000",
        "127.0.0.1:50000",
        "192.168.1.20:1900",
        "192.168.1.20:80",
        "192.168.1.10:50000",
        "192.168.1.255:50000",
        "[fe80::1]:50000",
        "[2a01:4f8:9:9::5]:50000",
    ];
    for from in refused {
        let (_, request) = peer.request();
        assert!(
            list.on_datagram(addr(from), Some(ip(OWN_V4)), &request, t0)
                .is_empty(),
            "{from}"
        );
    }
    let stats = list.stats();
    assert_eq!(stats.sources_refused, 9);
    assert_eq!((stats.responses_sent, stats.prflx_learned), (0, 0));
    assert!(list.targets.is_empty());
    assert!(gate.is_empty());
    assert!(list.heard_from_peer());
}

/// An IPv6 request is answered only when it reached an address this side
/// offered, and the response leaves from that address; an IPv4 request's
/// response leaves from the kernel's source.
#[test]
fn an_ipv6_request_is_answered_only_from_the_offered_address_it_reached() {
    let t0 = Instant::now();
    let (mut list, _) = checklist(PunchRole::Controlled, TornectRole::Viewer, Scope::SameSite);
    let peer = Peer::of(TornectRole::Viewer);
    let ula_peer = addr("[fd12:3456:789a:2::5]:50000");
    for dst in [
        None,
        Some(ip("fd12:3456:789a:1::99")),
        Some(ip(OWN_V4)),
        Some(ip("::1")),
    ] {
        let (_, request) = peer.request();
        assert!(list.on_datagram(ula_peer, dst, &request, t0).is_empty());
    }
    assert_eq!(list.stats().not_offered, 4, "loopback only where admitted");
    let (_, request) = peer.request();
    let out = sends(&list.on_datagram(ula_peer, Some(ip(OWN_ULA)), &request, t0));
    assert_eq!(out[0], (ula_peer, Some(ip(OWN_ULA)), out[0].2));
    assert!(peer.read(&out[0].2).response);
    assert_eq!(out[1].1, None, "a check's source is the link's choice");

    let (_, request) = peer.request();
    let out = sends(&list.on_datagram(
        addr("192.168.1.20:50000"),
        Some(ip("::ffff:192.168.1.10")),
        &request,
        t0,
    ));
    assert_eq!(out[0].1, None);
}

/// Where the filter admits loopback (the test environments of the link),
/// a request from IPv6 loopback reaching `::1` is answered from `::1`; the
/// same request is refused by a real side's filter (above).
#[test]
fn ipv6_loopback_is_answered_only_where_the_filter_admits_loopback() {
    let t0 = Instant::now();
    let mut filter = filter(Scope::SameSite);
    filter.admit_loopback = true;
    let mut list = Checklist::new(
        PunchRole::Controlled,
        TornectRole::Viewer,
        ProbeKey::derive(&TOKEN),
        filter,
        ProbeGate::new(),
        offered(),
    );
    let peer = Peer::of(TornectRole::Viewer);
    let from = addr("[::1]:50000");
    let (_, request) = peer.request();
    let out = sends(&list.on_datagram(from, Some(ip("::1")), &request, t0));
    assert_eq!(out[0].0, from);
    assert_eq!(out[0].1, Some(ip("::1")));
    assert!(peer.read(&out[0].2).response);
}

/// A reflection of one of this side's own probes, a probe under another
/// key, and a response all prove nothing about the peer.
#[test]
fn reflections_and_forgeries_are_dropped() {
    let t0 = Instant::now();
    let (mut list, _) = checklist(PunchRole::Controlled, TornectRole::Viewer, Scope::SameSite);
    let a = addr("192.168.1.20:50000");
    list.add_remote(host("192.168.1.20:50000"));
    let first = sends(&list.poll(t0));
    assert!(
        list.on_datagram(a, None, &first[0].2, t0 + ms(1))
            .is_empty()
    );
    let mine = ProbeKey::derive(&TOKEN);
    let reflected = mine
        .response(TornectRole::Viewer, &[3; 12])
        .expect("OS randomness");
    assert!(list.on_datagram(a, None, &reflected, t0 + ms(1)).is_empty());
    let stranger = ProbeKey::derive(&[0x44; 32]);
    let (_, forged) = stranger.request(TornectRole::Host).expect("OS randomness");
    assert!(list.on_datagram(a, None, &forged, t0 + ms(1)).is_empty());
    let stats = list.stats();
    assert_eq!((stats.own_role, stats.bad_tag), (2, 1));
    assert!(!list.heard_from_peer());
    assert!(!list.is_validated(a));
}

/// Nothing prints an address.
#[test]
fn no_debug_prints_an_address() {
    let t0 = Instant::now();
    let (mut list, _) = checklist(PunchRole::Controlling, TornectRole::Viewer, Scope::SameSite);
    let peer = Peer::of(TornectRole::Viewer);
    let a = addr("192.168.1.23:50123");
    list.add_remote(host("192.168.1.23:50123"));
    let first = list.poll(t0);
    let txid = peer.read(&sends(&first)[0].2).txid;
    list.on_datagram(a, None, &peer.response(&txid), t0 + ms(2));
    let log = drive(&mut list, t0 + ms(2), t0 + ms(500));
    let mut texts = vec![format!("{list:?}")];
    texts.extend(first.iter().map(|act| format!("{act:?}")));
    texts.extend(log.iter().map(|(_, act)| format!("{act:?}")));
    assert!(texts.iter().any(|t| t.starts_with("Nominate")));
    for text in texts {
        assert!(!text.contains("192.168"), "{text}");
        assert!(!text.contains("50123"), "{text}");
        assert!(!text.contains(".23"), "{text}");
    }
}

/// One side of the two-sided simulation below.
struct Side {
    list: Checklist,
    at: SocketAddr,
}

/// A datagram on its way.
struct Flight {
    deliver: Instant,
    to: SocketAddr,
    from: SocketAddr,
    bytes: [u8; PROBE_LEN],
}

/// What happened to the two sides of a simulated LAN session.
#[derive(Default)]
struct Outcome {
    validated: [Option<Instant>; 2],
    nominated: [Option<(Instant, SocketAddr)>; 2],
    failed: [bool; 2],
}

/// Two checklists on one LAN, 1 ms apart: the host gets the viewer's
/// candidates at `t0` (the viewer goes first), the viewer the host's at
/// `t0 + 500 ms` (a Tor one-way trip later). `lose` drops the n-th datagram
/// (counting from 0) when it returns true.
fn lan_session(
    viewer_controls: bool,
    t0: Instant,
    mut lose: impl FnMut(usize, &Flight) -> bool,
) -> (Outcome, [Side; 2]) {
    let viewer_at = addr("192.168.1.20:50000");
    let host_at = addr("192.168.1.30:50001");
    let (vp, hp) = if viewer_controls {
        (PunchRole::Controlling, PunchRole::Controlled)
    } else {
        (PunchRole::Controlled, PunchRole::Controlling)
    };
    let side = |punch, me, at: SocketAddr| Side {
        list: Checklist::new(
            punch,
            me,
            ProbeKey::derive(&TOKEN),
            filter_at(&at.ip().to_string(), Scope::SameSite),
            ProbeGate::new(),
            V6Sources::default(),
        ),
        at,
    };
    let mut sides = [
        side(vp, TornectRole::Viewer, viewer_at),
        side(hp, TornectRole::Host, host_at),
    ];
    let mut outcome = Outcome::default();
    let mut flights: Vec<Flight> = Vec::new();
    let mut count = 0;
    let mut now = t0;
    sides[1].list.add_remote(host("192.168.1.20:50000"));
    sides[1].list.remote_done();
    sides[0].list.local_done();
    sides[1].list.local_done();
    let mut viewer_told = false;
    let end = t0 + ms(5000);
    let mut handle = |k: usize,
                      actions: Vec<Action>,
                      now: Instant,
                      sides: &[Side; 2],
                      flights: &mut Vec<Flight>,
                      outcome: &mut Outcome| {
        for act in actions {
            match act {
                Action::Send { to, bytes, .. } => {
                    let flight = Flight {
                        deliver: now + ms(1),
                        to,
                        from: sides[k].at,
                        bytes,
                    };
                    if !lose(count, &flight) {
                        flights.push(flight);
                    }
                    count += 1;
                }
                Action::Nominate(to) => outcome.nominated[k] = Some((now, to)),
                Action::Failed => outcome.failed[k] = true,
            }
        }
    };
    loop {
        if !viewer_told && now >= t0 + ms(500) {
            viewer_told = true;
            sides[0].list.add_remote(host("192.168.1.30:50001"));
            sides[0].list.remote_done();
        }
        for k in 0..2 {
            let actions = sides[k].list.poll(now);
            handle(k, actions, now, &sides, &mut flights, &mut outcome);
        }
        let mut due: Vec<Flight> = Vec::new();
        let mut later: Vec<Flight> = Vec::new();
        for f in flights.drain(..) {
            if f.deliver <= now {
                due.push(f);
            } else {
                later.push(f);
            }
        }
        flights = later;
        for f in due {
            let Some(k) = sides.iter().position(|s| s.at == f.to) else {
                continue;
            };
            let dst = Some(sides[k].at.ip());
            let actions = sides[k].list.on_datagram(f.from, dst, &f.bytes, now);
            handle(k, actions, now, &sides, &mut flights, &mut outcome);
            if outcome.validated[k].is_none() && !sides[k].list.validated().is_empty() {
                outcome.validated[k] = Some(now);
            }
        }
        let mut next = end;
        for s in &sides {
            if let Some(w) = s.list.next_wakeup() {
                next = next.min(w);
            }
        }
        for f in &flights {
            next = next.min(f.deliver);
        }
        if !viewer_told {
            next = next.min(t0 + ms(500));
        }
        if next >= end {
            break;
        }
        now = next.max(now);
    }
    (outcome, sides)
}

/// On one LAN the viewer learns the host from its first request and
/// validates it with a triggered check, long before the host's candidates
/// arrive over Tor; the host validates the viewer with its own check; the
/// controlling side nominates the grace (100 ms) after its first round
/// trip. Whichever side controls.
#[test]
fn two_sides_on_one_lan_validate_before_the_hosts_candidates_arrive() {
    for viewer_controls in [true, false] {
        let t0 = Instant::now();
        let (outcome, sides) = lan_session(viewer_controls, t0, |_, _| false);
        let viewer_validated = outcome.validated[0].expect("the viewer validated the host");
        let host_validated = outcome.validated[1].expect("the host validated the viewer");
        assert!(viewer_validated <= t0 + ms(3), "{viewer_controls}");
        assert!(host_validated <= t0 + ms(3), "{viewer_controls}");
        let controller = usize::from(!viewer_controls);
        let (at, to) = outcome.nominated[controller].expect("a nomination");
        assert!(at <= t0 + ms(110), "{viewer_controls}");
        assert_eq!(to, sides[1 - controller].at);
        assert!(outcome.nominated[1 - controller].is_none());
        assert_eq!(outcome.failed, [false, false]);
        assert!(sides[0].list.is_validated(sides[1].at));
        assert!(sides[1].list.is_validated(sides[0].at));
        assert_eq!(
            sides[0].list.kind_of(sides[1].at),
            Some(CandidateKind::Host),
            "the host's candidate arrived and names the learned address"
        );
        for s in &sides {
            assert!(s.list.stats().requests_sent <= 8);
        }
    }
}

/// When the viewer's whole first answer is lost (its response and its
/// triggered check), the host's next scheduled request, 200 ms on, draws a
/// second response and a second triggered check, and both sides validate
/// then.
#[test]
fn a_lost_first_exchange_is_made_up_by_the_next_scheduled_request() {
    let t0 = Instant::now();
    let viewer_at = addr("192.168.1.20:50000");
    let mut lost = 0;
    let (outcome, sides) = lan_session(true, t0, |_, flight| {
        if flight.from == viewer_at && flight.deliver <= t0 + ms(2) {
            lost += 1;
            return true;
        }
        false
    });
    assert_eq!(lost, 2, "a response and a triggered check");
    let viewer_validated = outcome.validated[0].expect("validated after the loss");
    let host_validated = outcome.validated[1].expect("validated after the loss");
    for at in [viewer_validated, host_validated] {
        assert!(at >= t0 + ms(200) && at <= t0 + ms(203));
    }
    let (at, to) = outcome.nominated[0].expect("the viewer controls");
    assert_eq!(to, sides[1].at);
    assert!(at <= viewer_validated + GRACE_MIN + ms(1));
    let stats = sides[0].list.stats();
    assert_eq!(stats.triggered_sent, 2);
    assert_eq!(stats.responses_sent, 2);
    assert_eq!(outcome.failed, [false, false]);
}

/// A lost triggered check is never retransmitted on our timer (design
/// §7.6): the host, which validated the viewer from the viewer's response,
/// stops sending, and the viewer validates the host only when the host's
/// candidates arrive (500 ms, over Tor) and its own schedule starts.
#[test]
fn a_lost_triggered_check_is_never_retransmitted_on_our_timer() {
    let t0 = Instant::now();
    let viewer_at = addr("192.168.1.20:50000");
    let host_key = Peer::of(TornectRole::Host);
    let mut lost = 0;
    let (outcome, sides) = lan_session(true, t0, |_, flight| {
        let request = host_key
            .key
            .decode(TornectRole::Host, &flight.bytes)
            .is_ok_and(|p| !p.response);
        if flight.from == viewer_at && request && lost == 0 {
            lost += 1;
            return true;
        }
        false
    });
    assert_eq!(lost, 1);
    let host_validated = outcome.validated[1].expect("the viewer's response arrived");
    assert!(host_validated <= t0 + ms(3));
    let viewer_validated = outcome.validated[0].expect("validated by its own schedule");
    assert!(viewer_validated >= t0 + ms(500) && viewer_validated <= t0 + ms(503));
    let (at, to) = outcome.nominated[0].expect("the viewer controls");
    assert_eq!(to, sides[1].at);
    assert!(at >= viewer_validated + GRACE_MIN && at <= viewer_validated + GRACE_MIN + ms(1));
    let viewer = sides[0].list.stats();
    assert_eq!(viewer.triggered_sent, 1, "never retransmitted");
    assert_eq!(
        sides[1].list.stats().requests_sent,
        1,
        "the host stopped once validated"
    );
    assert_eq!(
        sides[0].list.kind_of(sides[1].at),
        Some(CandidateKind::Host)
    );
}

// The proptest: a checklist fed arbitrary inputs keeps every budget.

/// Addresses a peer (or a spoofer) may use: admitted and refused ones of
/// every class.
const POOL: [&str; 14] = [
    "192.168.1.20:50000",
    "192.168.1.21:50001",
    "[::ffff:192.168.1.22]:50002",
    "10.1.2.3:50000",
    "93.184.216.34:50000",
    "[2a01:4f8:9:9::5]:50000",
    "[fd12:3456:789a:2::5]:50000",
    "[fd99:1::5]:50000",
    "127.0.0.1:50000",
    "[fe80::1]:50000",
    "192.168.1.10:50000",
    "192.168.1.255:50000",
    "192.168.1.20:1900",
    "192.168.1.23:80",
];

/// Where a datagram may arrive.
const DSTS: [Option<&str>; 7] = [
    None,
    Some(OWN_V4),
    Some("::ffff:192.168.1.10"),
    Some(OWN_ULA),
    Some(OWN_GLOBAL_V6),
    Some("fd12:3456:789a:1::99"),
    Some("::1"),
];

#[derive(Debug, Clone)]
enum Op {
    Add(usize, usize),
    RemoteDone,
    LocalDone,
    LocalPublic(usize),
    Request(usize, usize),
    Replay(usize, usize, usize),
    Respond(usize, Option<usize>),
    Reflect(usize),
    Garbage(usize, Vec<u8>),
    Advance(u64),
}

fn op() -> impl Strategy<Value = Op> {
    let pool = 0..POOL.len();
    prop_oneof![
        3 => (pool.clone(), 0..4usize).prop_map(|(a, k)| Op::Add(a, k)),
        1 => Just(Op::RemoteDone),
        1 => Just(Op::LocalDone),
        1 => pool.clone().prop_map(Op::LocalPublic),
        6 => (pool.clone(), 0..DSTS.len()).prop_map(|(a, d)| Op::Request(a, d)),
        2 => (any::<usize>(), pool.clone(), 0..DSTS.len()).prop_map(|(k, a, d)| Op::Replay(k, a, d)),
        6 => (any::<usize>(), proptest::option::of(pool.clone())).prop_map(|(k, a)| Op::Respond(k, a)),
        1 => any::<usize>().prop_map(Op::Reflect),
        2 => (pool, proptest::collection::vec(any::<u8>(), 38..=42)).prop_map(|(a, b)| Op::Garbage(a, b)),
        4 => (0..700u64).prop_map(Op::Advance),
    ]
}

const KINDS: [CandidateKind; 4] = [
    CandidateKind::Host,
    CandidateKind::Srflx,
    CandidateKind::Mapped,
    CandidateKind::Prflx,
];

/// What the test saw the checklist do.
#[derive(Default)]
struct Ledger {
    requests_to: HashMap<SocketAddr, usize>,
    responses_to: HashMap<SocketAddr, usize>,
    bytes_to: HashMap<SocketAddr, usize>,
    total_bytes: usize,
    /// Our requests: (txid, canonical destination).
    ours: Vec<(Txid, SocketAddr)>,
    /// Every send, in order.
    sent: Vec<[u8; PROBE_LEN]>,
    /// Requests fed: txid → canonical sources it came from.
    fed: HashMap<Txid, HashSet<SocketAddr>>,
    fed_txids: Vec<Txid>,
    /// Txids our responses carried.
    answered: HashSet<Txid>,
    /// Addresses a response to one of our requests came from.
    round_trips: HashSet<SocketAddr>,
}

fn record(
    ledger: &mut Ledger,
    peer: &Peer,
    filter: &RemoteFilter,
    actions: &[Action],
) -> Result<(), TestCaseError> {
    for act in actions {
        let Action::Send { to, src, bytes } = *act else {
            continue;
        };
        prop_assert_eq!(to, canon(to));
        prop_assert!(filter.admit(to), "a send to a refused address");
        let probe = peer.read(&bytes);
        *ledger.bytes_to.entry(to).or_default() += PROBE_LEN;
        ledger.total_bytes += PROBE_LEN;
        ledger.sent.push(bytes);
        if probe.response {
            *ledger.responses_to.entry(to).or_default() += 1;
            prop_assert!(
                ledger
                    .fed
                    .get(&probe.txid)
                    .is_some_and(|from| from.contains(&to)),
                "a response to no request of that source"
            );
            prop_assert!(ledger.answered.insert(probe.txid), "a txid answered twice");
            match to.ip() {
                IpAddr::V4(_) => prop_assert_eq!(src, None),
                IpAddr::V6(_) => {
                    let from_offered = src.is_some_and(|s| match s {
                        IpAddr::V6(v6) => offered().offers(v6),
                        IpAddr::V4(_) => false,
                    });
                    prop_assert!(from_offered, "an IPv6 response from no offered address");
                }
            }
        } else {
            prop_assert_eq!(src, None);
            *ledger.requests_to.entry(to).or_default() += 1;
            ledger.ours.push((probe.txid, to));
        }
    }
    Ok(())
}

fn check_budgets(ledger: &Ledger, list: &Checklist, gate: &ProbeGate) -> Result<(), TestCaseError> {
    for count in ledger.requests_to.values() {
        prop_assert!(*count <= MAX_REQUESTS_PER_TARGET);
    }
    for count in ledger.responses_to.values() {
        prop_assert!(*count <= MAX_RESPONSES_PER_SOURCE);
    }
    for bytes in ledger.bytes_to.values() {
        prop_assert!(*bytes <= MAX_UNVALIDATED_BYTES);
    }
    prop_assert!(ledger.total_bytes <= MAX_PROBE_BYTES);
    prop_assert!(ledger.responses_to.values().sum::<usize>() <= MAX_RESPONSES);
    let validated = list.validated();
    prop_assert_eq!(gate.len(), validated.len());
    for a in &validated {
        prop_assert!(gate.admits(*a));
        prop_assert!(
            ledger.round_trips.contains(a),
            "validated without our round trip"
        );
    }
    prop_assert!(in_flight(list) <= MAX_IN_FLIGHT);
    prop_assert!(list.targets.len() <= MAX_TARGETS);
    prop_assert!(list.remote_count <= MAX_REMOTE_CANDIDATES);
    prop_assert!(list.prflx_count <= MAX_PRFLX);
    for t in &list.targets {
        prop_assert!(list.filter.admit(t.addr));
        prop_assert!(t.requests <= MAX_REQUESTS_PER_TARGET);
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Whatever arrives, in any order and at any time: no address gets
    /// more than four requests, eight responses or 480 bytes; the session
    /// sends at most 5760 bytes and 64 responses; every send goes to an
    /// admitted address; a response answers a request that came from its
    /// destination, once per txid; each datagram fed draws at most one
    /// response and one triggered check of its size (2:1); only our own
    /// round trips validate, and the gate holds exactly the validated
    /// addresses.
    #[test]
    fn every_budget_holds_over_arbitrary_inputs(
        ops in proptest::collection::vec(op(), 1..200),
        controlling in any::<bool>(),
        host_side in any::<bool>(),
        internet in any::<bool>(),
    ) {
        let t0 = Instant::now();
        let me = if host_side { TornectRole::Host } else { TornectRole::Viewer };
        let punch = if controlling { PunchRole::Controlling } else { PunchRole::Controlled };
        let scope = if internet { Scope::Internet } else { Scope::SameSite };
        let (mut list, gate) = checklist(punch, me, scope);
        let filter = filter(scope);
        let peer = Peer::of(me);
        let mine = ProbeKey::derive(&TOKEN);
        let mut ledger = Ledger::default();
        let mut now = t0;
        let mut fed = 0usize;
        let mut reactive = 0usize;
        for op in ops {
            let feed = match op {
                Op::Add(a, k) => {
                    list.add_remote(Candidate { kind: KINDS[k], addr: addr(POOL[a]) });
                    None
                }
                Op::RemoteDone => { list.remote_done(); None }
                Op::LocalDone => { list.local_done(); None }
                Op::LocalPublic(a) => { list.set_local_public(&[addr(POOL[a]).ip()]); None }
                Op::Request(a, d) => {
                    let (txid, bytes) = peer.request();
                    Some((addr(POOL[a]), DSTS[d].map(ip), bytes.to_vec(), Some(txid)))
                }
                Op::Replay(k, a, d) => {
                    if ledger.fed_txids.is_empty() {
                        None
                    } else {
                        let txid = ledger.fed_txids[k % ledger.fed_txids.len()];
                        Some((addr(POOL[a]), DSTS[d].map(ip), peer.request_with(&txid).to_vec(), Some(txid)))
                    }
                }
                Op::Respond(k, from) => {
                    if ledger.ours.is_empty() {
                        None
                    } else {
                        let (txid, to) = ledger.ours[k % ledger.ours.len()];
                        let from = from.map_or(to, |a| addr(POOL[a]));
                        if canon(from) == to {
                            ledger.round_trips.insert(to);
                        }
                        Some((from, None, peer.response(&txid).to_vec(), None))
                    }
                }
                Op::Reflect(k) => {
                    if ledger.sent.is_empty() {
                        None
                    } else {
                        let bytes = ledger.sent[k % ledger.sent.len()];
                        Some((addr(POOL[0]), None, bytes.to_vec(), None))
                    }
                }
                Op::Garbage(a, bytes) => Some((addr(POOL[a]), None, bytes, None)),
                Op::Advance(d) => {
                    now += ms(d);
                    let actions = list.poll(now);
                    record(&mut ledger, &peer, &filter, &actions)?;
                    None
                }
            };
            if let Some((from, dst, bytes, txid)) = feed {
                if let Some(txid) = txid {
                    ledger.fed.entry(txid).or_default().insert(canon(from));
                    ledger.fed_txids.push(txid);
                }
                let authenticated_request = mine
                    .decode(me, &bytes)
                    .is_ok_and(|p: Probe| !p.response);
                let actions = list.on_datagram(from, dst, &bytes, now);
                prop_assert!(actions.len() <= 2);
                let replies = sends(&actions);
                let responses = replies.iter().filter(|s| peer.read(&s.2).response).count();
                prop_assert!(responses <= 1);
                prop_assert!(replies.len() - responses <= 1);
                if !authenticated_request {
                    prop_assert!(replies.is_empty(), "a reply to an unauthenticated datagram");
                }
                fed += bytes.len();
                reactive += replies.len() * PROBE_LEN;
                prop_assert!(reactive <= 2 * fed, "more than two bytes out per byte in");
                record(&mut ledger, &peer, &filter, &actions)?;
            }
            check_budgets(&ledger, &list, &gate)?;
        }
        let end = now + ms(10_000);
        let log = drive(&mut list, now, end);
        let actions: Vec<Action> = log.into_iter().map(|(_, a)| a).collect();
        record(&mut ledger, &peer, &filter, &actions)?;
        check_budgets(&ledger, &list, &gate)?;
    }
}

// ---------------------------------------------------------------------------
// Ranks in internet scope over arbitrary public addresses (step B7).

/// Remote addresses for the rank property: on-link private, off-link
/// private, a ULA in and outside our /48, public IPv4 (some of which may be
/// ours), a global IPv6.
const RANK_POOL: [&str; 10] = [
    "192.168.1.20:50000",
    "192.168.1.21:50001",
    "10.1.2.3:50000",
    "172.16.5.5:50000",
    "[fd12:3456:789a:2::5]:50000",
    "[fd99:1::5]:50000",
    "93.184.216.34:50000",
    "93.184.216.35:40000",
    "81.2.3.4:40001",
    "[2a01:4f8:9:9::5]:50000",
];

/// Public addresses this side may have learned (a private one is ignored).
const PUBLICS: [&str; 5] = [
    "93.184.216.34",
    "93.184.216.35",
    "81.2.3.4",
    "81.2.3.99",
    "192.168.1.1",
];

const SIGNALLED: [CandidateKind; 3] = [
    CandidateKind::Host,
    CandidateKind::Srflx,
    CandidateKind::Mapped,
];

/// The design table (§7.6) restated for `addr` of `kind`, given whether it
/// is on our site, whether the two sides share a public IPv4 and whether
/// both know public addresses that differ: the rank, and whether the
/// target is on our site (the route label, §3.1).
fn table_rank(
    addr: SocketAddr,
    kind: CandidateKind,
    on_site: bool,
    same_nat: bool,
    differ: bool,
) -> (Rank, bool) {
    if on_site {
        return if differ {
            (Rank::OtherPrivate, false)
        } else {
            (Rank::SameSite, true)
        };
    }
    let ip = addr.ip();
    match (class(ip), ip.is_ipv4(), kind) {
        (AddrClass::Global, false, CandidateKind::Host) => (Rank::GlobalV6Host, false),
        (AddrClass::Global, true, CandidateKind::Host) => (Rank::PublicV4Host, false),
        (AddrClass::Private, true, _) if same_nat => (Rank::PublicV4Host, true),
        (_, _, CandidateKind::Mapped) => (Rank::Mapped, false),
        (_, _, CandidateKind::Srflx | CandidateKind::Prflx) => (Rank::Reflexive, false),
        (_, _, CandidateKind::Host) => (Rank::OtherPrivate, false),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Design §7.6 in internet scope, whatever the peer signals and
    /// whatever public addresses this side learned: every target's rank and
    /// same-site label follow the table (same-site demotion when both
    /// sides' public addresses differ, same-NAT promotion when they share
    /// one, never same-site for a global address); targets start in rank
    /// order; a same-site target checks on the same-site schedule and every
    /// other on the internet one.
    #[test]
    fn ranks_and_schedules_follow_the_public_addresses(
        adds in proptest::collection::vec((0..RANK_POOL.len(), 0..SIGNALLED.len()), 1..16),
        publics in proptest::collection::vec(0..PUBLICS.len(), 0..3),
        controlling in any::<bool>(),
    ) {
        let t0 = Instant::now();
        let punch = if controlling { PunchRole::Controlling } else { PunchRole::Controlled };
        let (mut list, _) = checklist(punch, TornectRole::Viewer, Scope::Internet);
        let mine: Vec<IpAddr> = publics.iter().map(|i| ip(PUBLICS[*i])).collect();
        list.set_local_public(&mine);
        for (a, k) in adds {
            list.add_remote(Candidate { kind: SIGNALLED[k], addr: addr(RANK_POOL[a]) });
        }
        let local: Vec<IpAddr> = mine
            .iter()
            .copied()
            .filter(|ip| ip.is_ipv4() && class(*ip) == AddrClass::Global)
            .collect();
        let remote: Vec<IpAddr> = list
            .targets
            .iter()
            .map(|t| t.addr.ip())
            .filter(|ip| ip.is_ipv4() && class(*ip) == AddrClass::Global)
            .collect();
        let same_nat = remote.iter().any(|ip| local.contains(ip));
        let differ = !local.is_empty() && !remote.is_empty() && !same_nat;
        let mut expected = Vec::new();
        for t in &list.targets {
            let on_site = list.filter.on_site(t.addr.ip());
            let (rank, same_site) = table_rank(t.addr, t.kind, on_site, same_nat, differ);
            prop_assert_eq!(list.rank(t.addr, t.kind), rank, "{:?}", t.kind);
            prop_assert_eq!(list.same_site(t.addr), same_site);
            if class(t.addr.ip()) == AddrClass::Global {
                prop_assert!(!same_site);
            }
            expected.push((t.addr, rank, t.seq, same_site));
        }

        let log = drive(&mut list, t0, t0 + ms(20_000));
        let mut starts: Vec<(Duration, Rank, usize)> = Vec::new();
        for (a, rank, seq, same_site) in expected {
            let times = send_times(&log, a, t0);
            prop_assert_eq!(times.len(), MAX_REQUESTS_PER_TARGET);
            let start = times[0];
            let schedule = if same_site { SAME_SITE_SCHEDULE } else { INTERNET_SCHEDULE };
            prop_assert_eq!(times, schedule.sends.map(|d| d + start).to_vec());
            starts.push((start, rank, seq));
        }
        starts.sort_unstable();
        for pair in starts.windows(2) {
            prop_assert!((pair[0].1, pair[0].2) < (pair[1].1, pair[1].2), "started out of rank order");
        }
    }
}
