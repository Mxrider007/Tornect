//! The session socket's demultiplexer and its two source gates (design
//! `direct` §6.3, §7.7; decisions M1-80, M1-83).
//!
//! One UDP socket per session carries the punch probes, STUN and QUIC.
//! [`PunchSocket`] sits between quinn and that socket ([`BoundUdp`]):
//!
//! - **Tees.** Every received datagram shaped like a probe (40 bytes, lead
//!   byte in [`PROBE_LEADS`]) or a STUN message is copied into a bounded side
//!   channel ([`Tees`]) for the checklist and the STUN client, whatever its
//!   source.
//! - **Receive gate.** quinn sees a datagram only if its source is in the
//!   [`ProbeGate`], the set of addresses a probe round trip validated.
//!   Anything else is handed to quinn with length 0, which its receive loop
//!   skips without a call into quinn-proto (`quinn-0.11.12`
//!   `src/endpoint.rs:798–799`): no Version Negotiation, Retry, stateless
//!   reset, refusal or handshake byte ever goes to an unvalidated source.
//! - **Send gate.** A quinn transmit to an address outside the gate is
//!   dropped and counted.
//! - **Family rule.** quinn sees every address as the socket reports it (on
//!   a dual-stack socket an IPv4 peer is `::ffff:a.b.c.d`, the form quinn
//!   stores a dial target in); the canonical form ([`canon`]) is used only
//!   for Tornect's own tables. Every IPv4 destination is v4-mapped on a
//!   dual-stack socket, because Windows and macOS refuse an `AF_INET`
//!   destination on an `AF_INET6` socket.
//! - **IPv6 source.** Every IPv6 datagram leaves from an address this side
//!   offered ([`V6Sources`]); one with no offered source of its class is
//!   dropped and counted.
//!
//! [`PunchSocket::send_raw`] is the only other way out: 40-byte probes and
//! 20-byte STUN requests. No address is ever logged; the counters
//! ([`PunchCounters`]) are the only record.

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::ops::RangeInclusive;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, ready};

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use tokio::sync::mpsc;

use crate::addr::{AddrClass, Count, Redacted, RedactedIp, canon, class_v6, to_socket_family};
use crate::socket::{BoundSocket, QuietUdp, SendErrors};

/// The size of a punch probe, request and response alike (design §6.2).
pub const PROBE_LEN: usize = 40;

/// The lead bytes of a punch probe: bit `0x40` clear, so never a QUIC
/// packet while the QUIC bit is not greased; at least `0x04`, so never STUN
/// (`0x00..=0x03`, RFC 9443).
pub const PROBE_LEADS: RangeInclusive<u8> = 0x04..=0x3F;

/// The size of a STUN Binding request without attributes (design §6.4).
pub const STUN_REQUEST_LEN: usize = 20;

/// The largest STUN message the tee takes (RFC 8489 §6.1: 548 bytes when
/// the path MTU is unknown).
pub const STUN_MAX_LEN: usize = 548;

/// The STUN magic cookie, bytes 4..8 of every STUN message (RFC 8489 §5).
pub const STUN_COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];

/// The capacity of the probe side channel; overflow is dropped and counted.
pub const PROBE_TEE: usize = 64;

/// The capacity of the STUN side channel; overflow is dropped and counted.
pub const STUN_TEE: usize = 8;

/// Whether `datagram` is shaped like a punch probe. Its tag is checked by
/// the checklist, not here.
#[must_use]
pub fn is_probe(datagram: &[u8]) -> bool {
    datagram.len() == PROBE_LEN && PROBE_LEADS.contains(&datagram[0])
}

/// Whether `datagram` is shaped like a STUN message: 20 to 548 bytes, the
/// first two bits clear, the magic cookie. The reply is parsed by the STUN
/// client, not here.
#[must_use]
pub fn is_stun(datagram: &[u8]) -> bool {
    (STUN_REQUEST_LEN..=STUN_MAX_LEN).contains(&datagram.len())
        && datagram[0] <= 0x03
        && datagram[4..8] == STUN_COOKIE
}

/// A session socket as a direct link receives it from
/// [`NetEnv::bind`](crate::NetEnv::bind): quinn's socket abstraction, its
/// family, and the counters of the sends the OS refused.
pub struct BoundUdp {
    /// The socket: [`QuietUdp`] on a real machine, an in-memory socket in
    /// tests.
    pub inner: Arc<dyn AsyncUdpSocket>,
    /// The socket carries IPv4 as v4-mapped IPv6 and IPv6 alike.
    pub dual_stack: bool,
    /// Sends the OS refused, counted instead of logged.
    pub errors: Arc<SendErrors>,
}

impl BoundUdp {
    /// A freshly bound socket of this machine, taken into the tokio runtime
    /// this is called on.
    ///
    /// # Errors
    ///
    /// As [`QuietUdp::new`].
    pub fn quiet(bound: BoundSocket) -> io::Result<Self> {
        let quiet = QuietUdp::new(bound.sock)?;
        let errors = quiet.errors();
        Ok(Self {
            inner: Arc::new(quiet),
            dual_stack: bound.dual_stack,
            errors,
        })
    }
}

impl fmt::Debug for BoundUdp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundUdp")
            .field("dual_stack", &self.dual_stack)
            .field("errors", &self.errors)
            .finish_non_exhaustive()
    }
}

/// The set of addresses a probe round trip validated (design §6.3, §7.7):
/// the only sources quinn hears and the only destinations it reaches.
/// Shared by the session socket and the checklist, which alone adds to it.
/// Addresses are kept in canonical form.
#[derive(Clone, Default)]
pub struct ProbeGate(Arc<Mutex<Vec<SocketAddr>>>);

impl ProbeGate {
    /// The most addresses the gate holds: the checklist's most targets (16
    /// remote candidates and 4 peer-reflexive ones), so the gate set can
    /// always equal the validated set.
    pub const CAPACITY: usize = 20;

    /// An empty gate.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Opens the gate for `addr` (a validated round trip). `false` if the
    /// gate is full and `addr` is not in it.
    pub fn admit(&self, addr: SocketAddr) -> bool {
        let addr = canon(addr);
        let mut set = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if set.contains(&addr) {
            return true;
        }
        if set.len() >= Self::CAPACITY {
            return false;
        }
        set.push(addr);
        true
    }

    /// Whether `addr` (in either family form) passes the gate.
    #[must_use]
    pub fn admits(&self, addr: SocketAddr) -> bool {
        let addr = canon(addr);
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&addr)
    }

    /// How many addresses pass.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).len()
    }

    /// Whether no address passes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl fmt::Debug for ProbeGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ProbeGate")
            .field(&Count(self.len(), "addresses"))
            .finish()
    }
}

/// The IPv6 addresses this side offered, which every IPv6 datagram must
/// leave from (design §5.2 rule 7, §6.3).
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct V6Sources {
    /// The offered global IPv6 address (at most one, design §7.1).
    pub global: Option<Ipv6Addr>,
    /// The offered unique-local address.
    pub ula: Option<Ipv6Addr>,
}

impl V6Sources {
    /// Whether `ip` is one of the offered addresses.
    #[must_use]
    pub fn offers(&self, ip: Ipv6Addr) -> bool {
        self.global == Some(ip) || self.ula == Some(ip)
    }

    /// The offered address a datagram to `dst` leaves from: the global one
    /// for a global destination, the unique-local one for a unique-local
    /// destination, none for any other class.
    #[must_use]
    pub fn for_destination(&self, dst: Ipv6Addr) -> Option<Ipv6Addr> {
        match class_v6(dst) {
            AddrClass::Global => self.global,
            AddrClass::UniqueLocal => self.ula,
            _ => None,
        }
    }
}

impl fmt::Debug for V6Sources {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V6Sources")
            .field("global", &self.global.is_some())
            .field("ula", &self.ula.is_some())
            .finish()
    }
}

/// The source of an IPv6 datagram to `dst`: `src` if it is an offered
/// address, otherwise the offered address of the destination's class;
/// `Err` when there is none (the datagram is dropped).
///
/// A loopback destination is the one exception: such a datagram never
/// leaves the machine, and the filters admit a loopback remote only in test
/// environments, so the kernel's source (or a loopback `src`) is kept.
fn v6_source(
    dst: Ipv6Addr,
    src: Option<IpAddr>,
    offered: &V6Sources,
) -> Result<Option<IpAddr>, ()> {
    if dst.is_loopback() {
        return match src {
            None => Ok(None),
            Some(IpAddr::V6(ip)) if ip.is_loopback() => Ok(src),
            Some(_) => Err(()),
        };
    }
    match src {
        Some(IpAddr::V6(ip)) if offered.offers(ip) => Ok(src),
        Some(_) => Err(()),
        None => offered
            .for_destination(dst)
            .map(|ip| Some(IpAddr::V6(ip)))
            .ok_or(()),
    }
}

/// A datagram the probe tee took (design §6.3 item 1).
pub struct TeedProbe {
    /// Its source, in canonical form.
    pub from: SocketAddr,
    /// The local address it reached, as the socket reported it (`None`
    /// where the OS does not say): a probe response leaves from it.
    pub dst_ip: Option<IpAddr>,
    /// The datagram.
    pub bytes: [u8; PROBE_LEN],
}

impl fmt::Debug for TeedProbe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TeedProbe")
            .field("from", &Redacted(&self.from))
            .field("dst_ip", &self.dst_ip.map(RedactedIp))
            .finish_non_exhaustive()
    }
}

/// A datagram the STUN tee took.
pub struct TeedStun {
    /// Its source, in canonical form.
    pub from: SocketAddr,
    /// The message (20 to [`STUN_MAX_LEN`] bytes).
    pub bytes: Vec<u8>,
}

impl fmt::Debug for TeedStun {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TeedStun")
            .field("from", &Redacted(&self.from))
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// The receiving ends of a [`PunchSocket`]'s side channels. They fill only
/// while quinn's endpoint driver polls the socket.
pub struct Tees {
    /// Probe-shaped datagrams, at most [`PROBE_TEE`] waiting.
    pub probes: mpsc::Receiver<TeedProbe>,
    /// STUN-shaped datagrams, at most [`STUN_TEE`] waiting.
    pub stun: mpsc::Receiver<TeedStun>,
}

impl fmt::Debug for Tees {
    /// The queue lengths only: tokio's own `Debug` of a receiver prints
    /// heap addresses.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tees")
            .field("probes_waiting", &self.probes.len())
            .field("stun_waiting", &self.stun.len())
            .finish()
    }
}

/// What became of a [`PunchSocket::send_raw`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawSend {
    /// Handed to the OS.
    Sent,
    /// The socket could not take it now; dropped. Either its send buffer
    /// is full, or the runtime has not seen the fresh socket writable yet
    /// ([`PunchSocket::writable`] waits for that).
    Blocked,
    /// No offered source address can carry it (an IPv6 destination with no
    /// offered address of its class, or with a source that was not offered;
    /// IPv6 on an IPv4-only socket); dropped.
    NoSource,
    /// Neither a probe ([`PROBE_LEN`]) nor a STUN request
    /// ([`STUN_REQUEST_LEN`]); refused.
    WrongLength,
    /// The socket refused it; dropped.
    Failed,
}

/// A snapshot of a [`PunchSocket`]'s counters (counts only, design §6.3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PunchCounters {
    /// Probes handed to the OS.
    pub probes_sent: u64,
    /// STUN requests handed to the OS.
    pub stun_sent: u64,
    /// Received datagrams hidden from quinn: their source is not validated.
    pub gated: u64,
    /// quinn transmits dropped: their destination is not validated.
    pub send_gated: u64,
    /// Datagrams dropped for want of an offered source address.
    pub no_source: u64,
    /// Teed datagrams dropped because their side channel was full or closed.
    pub teed_dropped: u64,
    /// Datagrams sent to an IPv4 peer in v4-mapped form (dual-stack socket).
    pub v4_mapped_sends: u64,
    /// Probes and STUN requests dropped because the socket could not take
    /// them now ([`RawSend::Blocked`]).
    pub raw_blocked: u64,
    /// Sends the inner socket refused with an error (an in-memory socket's
    /// refusal; [`QuietUdp`] swallows the OS's into the next two).
    pub inner_errors: u64,
    /// Sends the OS refused as too large for the path.
    pub os_too_large: u64,
    /// Every other send the OS refused.
    pub os_errors: u64,
}

#[derive(Default)]
struct Counters {
    probes_sent: AtomicU64,
    stun_sent: AtomicU64,
    gated: AtomicU64,
    send_gated: AtomicU64,
    no_source: AtomicU64,
    teed_dropped: AtomicU64,
    v4_mapped_sends: AtomicU64,
    raw_blocked: AtomicU64,
    inner_errors: AtomicU64,
}

fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

fn read(counter: &AtomicU64) -> u64 {
    counter.load(Ordering::Relaxed)
}

/// The session socket as quinn and the checklist share it (design §6.3):
/// tees, both source gates, the family rule and IPv6 source pinning over the
/// [`BoundUdp`] it wraps. quinn's endpoint is built on it with
/// `Endpoint::new_with_abstract_socket`.
pub struct PunchSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    dual_stack: bool,
    gate: ProbeGate,
    sources: Mutex<V6Sources>,
    probes: mpsc::Sender<TeedProbe>,
    stun: mpsc::Sender<TeedStun>,
    counts: Counters,
    os: Arc<SendErrors>,
}

impl PunchSocket {
    /// Wraps a bound session socket behind `gate`, with no IPv6 source
    /// offered yet.
    #[must_use]
    pub fn new(bound: BoundUdp, gate: ProbeGate) -> (Arc<Self>, Tees) {
        let (probes, probes_rx) = mpsc::channel(PROBE_TEE);
        let (stun, stun_rx) = mpsc::channel(STUN_TEE);
        let socket = Arc::new(Self {
            inner: bound.inner,
            dual_stack: bound.dual_stack,
            gate,
            sources: Mutex::new(V6Sources::default()),
            probes,
            stun,
            counts: Counters::default(),
            os: bound.errors,
        });
        (
            socket,
            Tees {
                probes: probes_rx,
                stun: stun_rx,
            },
        )
    }

    /// Whether the socket carries IPv4 as v4-mapped IPv6 (a dial target is
    /// passed through [`to_socket_family`] with this).
    #[must_use]
    pub fn dual_stack(&self) -> bool {
        self.dual_stack
    }

    /// The gate this socket applies.
    #[must_use]
    pub fn gate(&self) -> &ProbeGate {
        &self.gate
    }

    /// Sets the IPv6 addresses this side offered (design §6.3 "IPv6 source
    /// pinning"); set by the link from its candidates before any send.
    pub fn set_sources(&self, sources: V6Sources) {
        *self.sources.lock().unwrap_or_else(PoisonError::into_inner) = sources;
    }

    /// The IPv6 addresses this side offered.
    #[must_use]
    pub fn sources(&self) -> V6Sources {
        *self.sources.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Waits until the socket can take a datagram. The runtime reads a
    /// fresh socket as not writable until it has seen it once, so a link
    /// waits here before its first probe; quinn waits the same way on its
    /// own.
    ///
    /// # Errors
    ///
    /// The socket's readiness failed (the runtime is shutting down).
    pub async fn writable(&self) -> io::Result<()> {
        let mut poller = Arc::clone(&self.inner).create_io_poller();
        std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx)).await
    }

    /// A snapshot of the counters.
    #[must_use]
    pub fn counters(&self) -> PunchCounters {
        let c = &self.counts;
        PunchCounters {
            probes_sent: read(&c.probes_sent),
            stun_sent: read(&c.stun_sent),
            gated: read(&c.gated),
            send_gated: read(&c.send_gated),
            no_source: read(&c.no_source),
            teed_dropped: read(&c.teed_dropped),
            v4_mapped_sends: read(&c.v4_mapped_sends),
            raw_blocked: read(&c.raw_blocked),
            inner_errors: read(&c.inner_errors),
            os_too_large: self.os.too_large(),
            os_errors: self.os.other(),
        }
    }

    /// Sends a 40-byte probe or a 20-byte STUN request to `dst`, outside
    /// both gates: the checklist sends only to targets the remote filter
    /// admitted, the STUN client only to servers the STUN filter admitted.
    /// `src` is the address a probe request reached, for its response; an
    /// IPv6 datagram leaves from it only if it was offered, and otherwise
    /// from the offered address of the destination's class. IPv4 sources
    /// are left to the kernel (`src` is ignored). The destination is
    /// v4-mapped on a dual-stack socket.
    pub fn send_raw(&self, dst: SocketAddr, datagram: &[u8], src: Option<IpAddr>) -> RawSend {
        let sent = match datagram.len() {
            PROBE_LEN => &self.counts.probes_sent,
            STUN_REQUEST_LEN => &self.counts.stun_sent,
            _ => return RawSend::WrongLength,
        };
        let Some((destination, src_ip)) = self.route(canon(dst), src, true) else {
            return RawSend::NoSource;
        };
        let transmit = Transmit {
            destination,
            ecn: None,
            contents: datagram,
            segment_size: None,
            src_ip,
        };
        match self.inner.try_send(&transmit) {
            Ok(()) => {
                bump(sent);
                self.count_mapped(destination);
                RawSend::Sent
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                bump(&self.counts.raw_blocked);
                RawSend::Blocked
            }
            Err(_) => {
                bump(&self.counts.inner_errors);
                RawSend::Failed
            }
        }
    }

    /// The destination in the socket's family and the source of a datagram
    /// to `dst` (canonical); `None` (counted) when no offered source can
    /// carry it. `raw`: a probe or STUN request, whose IPv4 source is the
    /// kernel's; quinn's own IPv4 source (the address a peer reached) is
    /// passed through.
    fn route(
        &self,
        dst: SocketAddr,
        src: Option<IpAddr>,
        raw: bool,
    ) -> Option<(SocketAddr, Option<IpAddr>)> {
        match dst.ip() {
            IpAddr::V4(_) => Some((
                to_socket_family(dst, self.dual_stack),
                if raw { None } else { src },
            )),
            IpAddr::V6(v6) => {
                let source = if self.dual_stack {
                    v6_source(v6, src, &self.sources())
                } else {
                    Err(())
                };
                match source {
                    Ok(src_ip) => Some((dst, src_ip)),
                    Err(()) => {
                        bump(&self.counts.no_source);
                        None
                    }
                }
            }
        }
    }

    fn count_mapped(&self, destination: SocketAddr) {
        if let SocketAddr::V6(v6) = destination
            && v6.ip().to_ipv4_mapped().is_some()
        {
            bump(&self.counts.v4_mapped_sends);
        }
    }

    /// Copies a probe- or STUN-shaped datagram into its side channel.
    fn tee(&self, from: SocketAddr, dst_ip: Option<IpAddr>, datagram: &[u8]) {
        let full = if is_probe(datagram) {
            let mut bytes = [0; PROBE_LEN];
            bytes.copy_from_slice(datagram);
            self.probes
                .try_send(TeedProbe {
                    from,
                    dst_ip,
                    bytes,
                })
                .is_err()
        } else if is_stun(datagram) {
            self.stun
                .try_send(TeedStun {
                    from,
                    bytes: datagram.to_vec(),
                })
                .is_err()
        } else {
            false
        };
        if full {
            bump(&self.counts.teed_dropped);
        }
    }
}

impl fmt::Debug for PunchSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PunchSocket")
            .field("dual_stack", &self.dual_stack)
            .field("gate", &self.gate)
            .field("sources", &self.sources())
            .field("counters", &self.counters())
            .finish_non_exhaustive()
    }
}

impl AsyncUdpSocket for PunchSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Arc::clone(&self.inner).create_io_poller()
    }

    /// quinn's way out: only to validated destinations, in the socket's
    /// family, IPv6 from an offered address. A send the inner socket refuses
    /// is counted and reported as sent, so a UDP error never ends quinn's
    /// connection driver (`quinn-0.11.12` `src/connection.rs:1061`).
    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let dst = canon(transmit.destination);
        if !self.gate.admits(dst) {
            bump(&self.counts.send_gated);
            return Ok(());
        }
        let Some((destination, src_ip)) = self.route(dst, transmit.src_ip, false) else {
            return Ok(());
        };
        let out = Transmit {
            destination,
            ecn: transmit.ecn,
            contents: transmit.contents,
            segment_size: transmit.segment_size,
            src_ip,
        };
        match self.inner.try_send(&out) {
            Ok(()) => {
                self.count_mapped(destination);
                Ok(())
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Err(e),
            Err(_) => {
                bump(&self.counts.inner_errors);
                Ok(())
            }
        }
    }

    /// Tees every probe and STUN segment, then hides from quinn every
    /// entry whose source is not validated (its length set to 0). A GRO
    /// entry comes from one source, so the gate applies to it whole; its
    /// segments are `stride` bytes apart. `RecvMeta.addr` is never
    /// rewritten.
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let n = ready!(self.inner.poll_recv(cx, bufs, meta))?;
        for (m, buf) in meta.iter_mut().zip(bufs.iter()).take(n) {
            let from = canon(m.addr);
            let data = &buf[..m.len.min(buf.len())];
            let stride = if m.stride == 0 { data.len() } else { m.stride }.max(1);
            for segment in data.chunks(stride) {
                self.tee(from, m.dst_ip, segment);
            }
            if !self.gate.admits(from) {
                let hidden = data.len().div_ceil(stride) as u64;
                self.counts.gated.fetch_add(hidden, Ordering::Relaxed);
                m.len = 0;
            }
        }
        Poll::Ready(Ok(n))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[cfg(test)]
mod tests;
