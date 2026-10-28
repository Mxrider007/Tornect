//! The punch probe and the checklist (design `direct` §6.2, §7.6, §7.7;
//! decision M1-80) fed arbitrary bytes, read three ways:
//!
//! - **as a datagram:** `ProbeKey::decode` never panics, and whatever it
//!   accepts is exactly what `seal` makes of the fields it read (the decoder
//!   accepts the sealer's output and nothing else);
//! - **as probe fields:** a txid, the noise and a bit index; the sealed probe
//!   decodes back to its fields for the other role, is refused for its own
//!   role (a reflection), and with any one bit flipped is refused;
//! - **as a script** against one `Checklist`: candidates, peer requests
//!   (fresh, replayed, from refused sources, to unoffered addresses),
//!   responses (to our requests, from the wrong address), reflections of
//!   our own probes, garbage and the clock. After every step the budgets of
//!   §7.7 hold: at most four requests, eight responses and 480 bytes to any
//!   address, 5760 bytes and 64 responses in all; a send only to an admitted
//!   address; a response only to an authenticated request that came from
//!   its destination, once per txid, from an offered address (IPv6); per
//!   datagram fed at most one response and one triggered check, nothing for
//!   an unauthenticated one, never more than two bytes out per byte in; only
//!   our own round trips validate, and the gate holds exactly the validated
//!   addresses.
//!
//! ```text
//! cargo +nightly fuzz run probe target/fuzz-corpus/probe fuzz/seeds/probe -- -max_total_time=600
//! ```
//!
//! Corpus policy (decision M1-36): `fuzz/seeds/probe/` holds the committed
//! seeds: the known-answer request and response of
//! `tornect_net::probe::tests` (checked by
//! `the_fuzz_seeds_are_the_known_answers`) and two scripts; campaigns write
//! to `target/fuzz-corpus/probe`.

#![no_main]

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use libfuzzer_sys::fuzz_target;
use tornect_net::checklist::{
    MAX_PROBE_BYTES, MAX_REQUESTS_PER_TARGET, MAX_RESPONSES, MAX_RESPONSES_PER_SOURCE, MAX_TARGETS,
    MAX_UNVALIDATED_BYTES,
};
use tornect_net::probe::{NOISE_LEN, TXID_LEN};
use tornect_net::udp::PROBE_LEN;
use tornect_net::{
    Action, Candidate, CandidateKind, Checklist, Probe, ProbeDrop, ProbeGate, ProbeKey, PunchRole,
    RemoteFilter, Scope, TornectRole, Txid, V6Sources, canon,
};

/// The session token of the known answers (`probe::tests`).
const TOKEN: [u8; 32] = [0x11; 32];

const OWN_V4: &str = "192.168.1.10";
const OWN_ULA: &str = "fd12:3456:789a:1::10";
const OWN_GLOBAL_V6: &str = "2a01:4f8:1:2::10";

/// Addresses a peer or a spoofer may use: admitted and refused ones of every
/// class (as the checklist's proptest).
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

const KINDS: [CandidateKind; 4] = [
    CandidateKind::Host,
    CandidateKind::Srflx,
    CandidateKind::Mapped,
    CandidateKind::Prflx,
];

/// The longest a script runs, so one input stays fast.
const MAX_OPS: usize = 256;

fn other(role: TornectRole) -> TornectRole {
    match role {
        TornectRole::Viewer => TornectRole::Host,
        TornectRole::Host => TornectRole::Viewer,
    }
}

fn addr(text: &str) -> SocketAddr {
    text.parse().expect("a socket address")
}

fn ip(text: &str) -> IpAddr {
    text.parse().expect("an IP address")
}

fn offered() -> V6Sources {
    V6Sources {
        global: Some(OWN_GLOBAL_V6.parse().expect("an IPv6 address")),
        ula: Some(OWN_ULA.parse().expect("an IPv6 address")),
    }
}

fn filter(scope: Scope) -> RemoteFilter {
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
        tunnel_route: None,
        own: vec![ip(OWN_V4), ip(OWN_ULA), ip(OWN_GLOBAL_V6)],
        admit_loopback: false,
    }
}

/// Part one: the datagram as it arrives.
fn decode(key: &ProbeKey, data: &[u8]) {
    for receiver in [TornectRole::Viewer, TornectRole::Host] {
        let Ok(probe) = key.decode(receiver, data) else {
            continue;
        };
        assert_ne!(probe.sender, receiver);
        let mut noise = [0u8; NOISE_LEN];
        noise[0] = data[0] - 0x04;
        noise[1] = data[13];
        noise[2..].copy_from_slice(&data[14..24]);
        let sealed = key.seal(probe.response, probe.sender, &probe.txid, &noise);
        assert_eq!(
            &sealed[..],
            data,
            "accepted bytes the sealer would not make"
        );
    }
}

/// Part two: the data as the fields of a probe.
fn fields(key: &ProbeKey, data: &[u8]) {
    let Some((head, rest)) = data.split_first() else {
        return;
    };
    if rest.len() < TXID_LEN + NOISE_LEN + 2 {
        return;
    }
    let mut txid: Txid = [0; TXID_LEN];
    txid.copy_from_slice(&rest[..TXID_LEN]);
    let mut noise = [0u8; NOISE_LEN];
    noise.copy_from_slice(&rest[TXID_LEN..TXID_LEN + NOISE_LEN]);
    let bit = usize::from(u16::from_be_bytes([
        rest[TXID_LEN + NOISE_LEN],
        rest[TXID_LEN + NOISE_LEN + 1],
    ])) % (PROBE_LEN * 8);
    let response = head & 1 != 0;
    let sender = if head & 2 != 0 {
        TornectRole::Host
    } else {
        TornectRole::Viewer
    };
    let mut probe = key.seal(response, sender, &txid, &noise);
    assert_eq!(
        key.decode(other(sender), &probe),
        Ok(Probe {
            response,
            sender,
            txid
        })
    );
    assert_eq!(key.decode(sender, &probe), Err(ProbeDrop::OwnRole));
    probe[bit / 8] ^= 1 << (bit % 8);
    let read = key.decode(other(sender), &probe);
    assert!(
        matches!(read, Err(ProbeDrop::Shape | ProbeDrop::Tag)),
        "a flipped bit {bit} was accepted: {read:?}"
    );
}

/// The script's reader: missing bytes read as zero, and the script ends
/// with the data.
struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn byte(&mut self) -> u8 {
        match self.0.split_first() {
            Some((b, rest)) => {
                self.0 = rest;
                *b
            }
            None => 0,
        }
    }

    fn pick(&mut self, n: usize) -> usize {
        usize::from(self.byte()) % n
    }

    fn txid(&mut self) -> Txid {
        let mut txid = [0; TXID_LEN];
        for b in &mut txid {
            *b = self.byte();
        }
        txid
    }
}

/// What the harness saw the checklist do.
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
    /// Authenticated requests fed: txid → canonical sources.
    fed: HashMap<Txid, HashSet<SocketAddr>>,
    fed_txids: Vec<Txid>,
    answered: HashSet<Txid>,
    /// Addresses a response to one of our requests came from.
    round_trips: HashSet<SocketAddr>,
}

struct Harness {
    list: Checklist,
    gate: ProbeGate,
    filter: RemoteFilter,
    key: ProbeKey,
    me: TornectRole,
    ledger: Ledger,
}

impl Harness {
    fn record(&mut self, actions: &[Action]) {
        for act in actions {
            let Action::Send { to, src, bytes } = *act else {
                continue;
            };
            assert_eq!(to, canon(to));
            assert!(self.filter.admit(to), "a send to a refused address");
            let probe = self
                .key
                .decode(other(self.me), &bytes)
                .expect("every send is a probe for the peer");
            let l = &mut self.ledger;
            *l.bytes_to.entry(to).or_default() += PROBE_LEN;
            l.total_bytes += PROBE_LEN;
            l.sent.push(bytes);
            if probe.response {
                *l.responses_to.entry(to).or_default() += 1;
                assert!(
                    l.fed
                        .get(&probe.txid)
                        .is_some_and(|from| from.contains(&to)),
                    "a response to no request of that source"
                );
                assert!(l.answered.insert(probe.txid), "a txid answered twice");
                match to.ip() {
                    IpAddr::V4(_) => assert_eq!(src, None),
                    IpAddr::V6(_) => assert!(
                        matches!(src, Some(IpAddr::V6(s)) if offered().offers(s)),
                        "an IPv6 response from no offered address"
                    ),
                }
            } else {
                assert_eq!(src, None);
                *l.requests_to.entry(to).or_default() += 1;
                l.ours.push((probe.txid, to));
            }
        }
    }

    fn check(&self) {
        let l = &self.ledger;
        assert!(
            l.requests_to
                .values()
                .all(|n| *n <= MAX_REQUESTS_PER_TARGET)
        );
        assert!(
            l.responses_to
                .values()
                .all(|n| *n <= MAX_RESPONSES_PER_SOURCE)
        );
        assert!(l.bytes_to.values().all(|n| *n <= MAX_UNVALIDATED_BYTES));
        assert!(l.requests_to.len() <= MAX_TARGETS);
        assert!(l.total_bytes <= MAX_PROBE_BYTES);
        assert!(l.responses_to.values().sum::<usize>() <= MAX_RESPONSES);
        let validated = self.list.validated();
        assert_eq!(
            self.gate.len(),
            validated.len(),
            "the gate is the validated set"
        );
        for a in &validated {
            assert!(self.gate.admits(*a));
            assert!(
                l.round_trips.contains(a),
                "validated without our round trip"
            );
        }
    }

    /// Feeds one datagram and checks what it drew.
    fn feed(&mut self, from: SocketAddr, dst: Option<IpAddr>, bytes: &[u8], now: Instant) {
        let authenticated_request = self.key.decode(self.me, bytes).is_ok_and(|p| !p.response);
        let actions = self.list.on_datagram(from, dst, bytes, now);
        let mut responses = 0;
        let mut checks = 0;
        for act in &actions {
            match act {
                Action::Send { bytes, .. } => {
                    let probe = self
                        .key
                        .decode(other(self.me), bytes)
                        .expect("a probe for the peer");
                    if probe.response {
                        responses += 1;
                    } else {
                        checks += 1;
                    }
                }
                act => panic!("a datagram drew {act:?}"),
            }
        }
        assert!(responses <= 1 && checks <= 1, "more than one of each");
        assert!(
            authenticated_request || actions.is_empty(),
            "a reply to an unauthenticated datagram"
        );
        assert!(
            (responses + checks) * PROBE_LEN <= 2 * bytes.len(),
            "above 2:1"
        );
        self.record(&actions);
    }
}

/// Part three: the data as a script.
fn script(data: &[u8]) {
    let mut r = Reader(data);
    let config = r.byte();
    let me = if config & 2 != 0 {
        TornectRole::Host
    } else {
        TornectRole::Viewer
    };
    let punch = if config & 1 != 0 {
        PunchRole::Controlling
    } else {
        PunchRole::Controlled
    };
    let scope = if config & 4 != 0 {
        Scope::Internet
    } else {
        Scope::SameSite
    };
    let gate = ProbeGate::new();
    let list = Checklist::new(
        punch,
        me,
        ProbeKey::derive(&TOKEN),
        filter(scope),
        gate.clone(),
        offered(),
    );
    let mut h = Harness {
        list,
        gate,
        filter: filter(scope),
        key: ProbeKey::derive(&TOKEN),
        me,
        ledger: Ledger::default(),
    };
    let peer = other(me);
    let t0 = Instant::now();
    let mut now = t0;
    let mut fed = 0usize;
    let mut drawn = 0usize;
    for _ in 0..MAX_OPS {
        if r.0.is_empty() {
            break;
        }
        let sent_before = h.ledger.sent.len();
        let mut fed_now = 0;
        let op = r.byte() % 10;
        match op {
            0 => {
                let a = POOL[r.pick(POOL.len())];
                let kind = KINDS[r.pick(KINDS.len())];
                h.list.add_remote(Candidate {
                    kind,
                    addr: addr(a),
                });
            }
            1 => h.list.remote_done(),
            2 => h.list.local_done(),
            3 => {
                let a = addr(POOL[r.pick(POOL.len())]);
                h.list.set_local_public(&[a.ip()]);
            }
            4 | 5 => {
                // 4: a fresh request; 5: a replay of one already fed.
                let replay = op == 5 && !h.ledger.fed_txids.is_empty();
                let txid = if replay {
                    h.ledger.fed_txids[r.pick(h.ledger.fed_txids.len())]
                } else {
                    r.txid()
                };
                let from = addr(POOL[r.pick(POOL.len())]);
                let dst = DSTS[r.pick(DSTS.len())].map(ip);
                let bytes = h.key.seal(false, peer, &txid, &[r.byte(); NOISE_LEN]);
                h.ledger.fed.entry(txid).or_default().insert(canon(from));
                h.ledger.fed_txids.push(txid);
                h.feed(from, dst, &bytes, now);
                fed_now = PROBE_LEN;
            }
            6 => {
                if !h.ledger.ours.is_empty() {
                    let (txid, to) = h.ledger.ours[r.pick(h.ledger.ours.len())];
                    let choice = r.byte();
                    let from = if choice == 0xff {
                        to
                    } else {
                        addr(POOL[usize::from(choice) % POOL.len()])
                    };
                    if canon(from) == to {
                        h.ledger.round_trips.insert(to);
                    }
                    let bytes = h.key.seal(true, peer, &txid, &[r.byte(); NOISE_LEN]);
                    h.feed(from, None, &bytes, now);
                    fed_now = PROBE_LEN;
                }
            }
            7 => {
                if !h.ledger.sent.is_empty() {
                    let bytes = h.ledger.sent[r.pick(h.ledger.sent.len())];
                    let from = addr(POOL[r.pick(POOL.len())]);
                    h.feed(from, None, &bytes, now);
                    fed_now = PROBE_LEN;
                }
            }
            8 => {
                let from = addr(POOL[r.pick(POOL.len())]);
                let len = 38 + r.pick(5);
                let bytes: Vec<u8> = (0..len).map(|_| r.byte()).collect();
                h.feed(from, None, &bytes, now);
                fed_now = len;
            }
            _ => {
                let step = u16::from_be_bytes([r.byte(), r.byte()]) % 4001;
                now += Duration::from_millis(u64::from(step));
                let actions = h.list.poll(now);
                h.record(&actions);
            }
        }
        if fed_now > 0 {
            fed += fed_now;
            drawn += (h.ledger.sent.len() - sent_before) * PROBE_LEN;
            assert!(drawn <= 2 * fed, "more than two bytes out per byte in");
        }
        h.check();
    }
    // Run every timer out.
    let end = now + Duration::from_secs(10);
    let mut steps = 0;
    while let Some(at) = h.list.next_wakeup() {
        if at > end || steps > 10_000 {
            break;
        }
        now = now.max(at);
        let actions = h.list.poll(now);
        h.record(&actions);
        h.check();
        steps += 1;
        if h.list.next_wakeup().is_some_and(|next| next <= now) {
            // A wakeup that does not move on: poll once more, then stop.
            let actions = h.list.poll(now);
            h.record(&actions);
            h.check();
            if h.list.next_wakeup().is_some_and(|next| next <= now) {
                panic!("a wakeup that never passes");
            }
        }
    }
    h.check();
}

fuzz_target!(|data: &[u8]| {
    let key = ProbeKey::derive(&TOKEN);
    decode(&key, data);
    fields(&key, data);
    script(data);
});
