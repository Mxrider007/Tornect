//! The session's one UDP socket as the operating system holds it (design
//! `direct` §6.3; decisions M1-80, M1-83): [`bind_media_socket`] binds it,
//! dual-stack where the OS has IPv6, and [`QuietUdp`] hands it to quinn.
//!
//! [`QuietUdp`] mirrors quinn's own tokio socket (`quinn-0.11.12`
//! `src/runtime/tokio.rs` :50–102) with one change: a failed send is counted
//! in [`SendErrors`] and swallowed, never logged. quinn's socket calls
//! `UdpSocketState::send`, which writes both addresses of a failed send at
//! WARN (`quinn-udp-0.5.16` `log_sendmsg_error`, `src/lib.rs:158`); this one
//! calls `UdpSocketState::try_send` and records only the kind of the error.

use std::fmt;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, ready};

use quinn::udp::{RecvMeta, Transmit, UdpSocketState};
use quinn::{AsyncUdpSocket, UdpPoller};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::Interest;

/// The receive buffer asked for (best effort: the OS may cap it, for
/// example at `net.core.rmem_max` on Linux).
pub const RECV_BUFFER: usize = 2 << 20;

/// A freshly bound session socket, not yet handed to quinn.
pub struct BoundSocket {
    /// The socket, non-blocking, bound to the unspecified address of its
    /// family.
    pub sock: std::net::UdpSocket,
    /// Bound to `[::]` with `IPV6_V6ONLY` off: it carries IPv4 as
    /// v4-mapped IPv6 and IPv6 alike. `false`: bound to `0.0.0.0`, IPv4
    /// only.
    pub dual_stack: bool,
}

impl fmt::Debug for BoundSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundSocket")
            .field("dual_stack", &self.dual_stack)
            .finish_non_exhaustive()
    }
}

/// Binds the session's UDP socket (design §6.3).
///
/// - `[::]:port` with `IPV6_V6ONLY` off first (Windows defaults to on, so
///   it is always set); if the OS refuses (no `AF_INET6`, as in a container
///   without IPv6), `0.0.0.0:port`.
/// - A fixed `port` that is busy is retried once with 0 (any port).
/// - No `SO_REUSEADDR`: no other socket shares the port.
/// - A [`RECV_BUFFER`] receive buffer, best effort.
///
/// `port` 0 and `None` both mean "any port".
///
/// # Errors
///
/// The IPv4 attempt's error when neither family can be bound.
pub fn bind_media_socket(port: Option<u16>) -> io::Result<BoundSocket> {
    match bind_family(true, port) {
        Ok(sock) => Ok(BoundSocket {
            sock,
            dual_stack: true,
        }),
        Err(_) => bind_family(false, port).map(|sock| BoundSocket {
            sock,
            dual_stack: false,
        }),
    }
}

/// [`bind_once`] on `port`, then once on any port if `port` was busy.
fn bind_family(dual_stack: bool, port: Option<u16>) -> io::Result<std::net::UdpSocket> {
    let fixed = port.unwrap_or(0);
    match bind_once(dual_stack, fixed) {
        Err(e) if fixed != 0 && e.kind() == io::ErrorKind::AddrInUse => bind_once(dual_stack, 0),
        other => other,
    }
}

fn bind_once(dual_stack: bool, port: u16) -> io::Result<std::net::UdpSocket> {
    let (domain, addr) = if dual_stack {
        (
            Domain::IPV6,
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)),
        )
    } else {
        (
            Domain::IPV4,
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)),
        )
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if dual_stack {
        sock.set_only_v6(false)?;
    }
    // Best effort: a smaller buffer only drops more under a burst.
    let _ = sock.set_recv_buffer_size(RECV_BUFFER);
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    Ok(sock.into())
}

/// The OS error code of a datagram too large for the path (`EMSGSIZE`,
/// `WSAEMSGSIZE`); `None` where it is not known.
#[cfg(any(target_os = "linux", target_os = "android"))]
const EMSGSIZE: Option<i32> = Some(90);
#[cfg(any(
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
const EMSGSIZE: Option<i32> = Some(40);
#[cfg(windows)]
const EMSGSIZE: Option<i32> = Some(10040);
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    windows
)))]
const EMSGSIZE: Option<i32> = None;

/// Failed sends of one session socket, counted instead of logged (decision
/// M1-83). Shared by the socket and whoever reads its statistics.
#[derive(Debug, Default)]
pub struct SendErrors {
    too_large: AtomicU64,
    other: AtomicU64,
}

impl SendErrors {
    /// Counts one failed send by its kind; nothing else of the error is kept.
    pub fn record(&self, error: &io::Error) {
        let counter = if EMSGSIZE.is_some() && error.raw_os_error() == EMSGSIZE {
            &self.too_large
        } else {
            &self.other
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Datagrams refused as too large for the path (quinn's MTU probes
    /// expect some).
    #[must_use]
    pub fn too_large(&self) -> u64 {
        self.too_large.load(Ordering::Relaxed)
    }

    /// Every other failed send (an unreachable network, a refused family,
    /// a closed socket).
    #[must_use]
    pub fn other(&self) -> u64 {
        self.other.load(Ordering::Relaxed)
    }
}

/// quinn's tokio UDP socket without its send-error log (design §6.3, item
/// 1): all seven [`AsyncUdpSocket`] methods, as `quinn-0.11.12`
/// `src/runtime/tokio.rs` implements them, except that `try_send` goes
/// through `UdpSocketState::try_send` and counts every error but
/// `WouldBlock` in [`SendErrors`].
pub struct QuietUdp {
    io: tokio::net::UdpSocket,
    state: UdpSocketState,
    errors: Arc<SendErrors>,
}

impl QuietUdp {
    /// Takes a bound socket (from [`bind_media_socket`]) into the tokio
    /// runtime this is called on, with quinn-udp's socket options set
    /// (non-blocking, packet information, no fragmentation, GRO where the
    /// OS has it).
    ///
    /// # Errors
    ///
    /// Outside a tokio runtime, or when the OS refuses an option quinn-udp
    /// needs.
    pub fn new(sock: std::net::UdpSocket) -> io::Result<Self> {
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(io::Error::other(
                "the session socket needs the async runtime",
            ));
        }
        let state = UdpSocketState::new((&sock).into())?;
        let io = tokio::net::UdpSocket::from_std(sock)?;
        Ok(Self {
            io,
            state,
            errors: Arc::default(),
        })
    }

    /// The failed-send counters of this socket.
    #[must_use]
    pub fn errors(&self) -> Arc<SendErrors> {
        Arc::clone(&self.errors)
    }
}

impl fmt::Debug for QuietUdp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // tokio's own `Debug` would print the bound address.
        f.debug_struct("QuietUdp")
            .field("errors", &self.errors)
            .finish_non_exhaustive()
    }
}

impl AsyncUdpSocket for QuietUdp {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Writable {
            socket: self,
            fut: None,
        })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let sent = self.io.try_io(Interest::WRITABLE, || {
            self.state.try_send((&self.io).into(), transmit)
        });
        match sent {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Err(e),
            Err(e) => {
                // UDP is unreliable anyway: quinn retransmits, the probes
                // and STUN have their own schedules.
                self.errors.record(&e);
                Ok(())
            }
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.io.poll_recv_ready(cx))?;
            if let Ok(n) = self.io.try_io(Interest::READABLE, || {
                self.state.recv((&self.io).into(), bufs, meta)
            }) {
                return Poll::Ready(Ok(n));
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.state.max_gso_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.state.gro_segments()
    }

    fn may_fragment(&self) -> bool {
        self.state.may_fragment()
    }
}

/// A future that waits until the socket is writable.
type WritableFuture = Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync>>;

/// The [`UdpPoller`] of a [`QuietUdp`]: one `writable()` wait at a time,
/// renewed after each readiness (quinn's `UdpPollHelper`, which is private).
struct Writable {
    socket: Arc<QuietUdp>,
    fut: Option<WritableFuture>,
}

impl fmt::Debug for Writable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Writable")
            .field("waiting", &self.fut.is_some())
            .finish_non_exhaustive()
    }
}

impl UdpPoller for Writable {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let fut = this.fut.get_or_insert_with(|| {
            let socket = Arc::clone(&this.socket);
            Box::pin(async move { socket.io.writable().await })
        });
        let ready = fut.as_mut().poll(cx);
        if ready.is_ready() {
            this.fut = None;
        }
        ready
    }
}

#[cfg(test)]
mod tests;
