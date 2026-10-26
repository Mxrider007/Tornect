//! Test environments for direct links (design `direct` §8.3 `mem.rs`,
//! §12.2, §12.3): machines a [`NetEnv`] can stand for without a real
//! network, built only for tests (`cfg(test)`) and for other crates' tests
//! through the `test-support` feature, which only dev-dependencies enable.
//! `cargo xtask dist` checks that no release build carries it (design §8.8).
//!
//! - [`LoopbackNet`]: real UDP sockets on `127.0.0.x`, presented as one
//!   physical interface whose `127.0.0.0/8` counts as the private on-link
//!   prefix. It is the classification override a loopback session needs,
//!   since the loopback class is never offered or admitted on a real
//!   machine: it admits loopback remotes ([`NetEnv::admit_loopback`]), and
//!   only test environments do (`RealNet` never does).

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use socket2::{Domain, Protocol, Socket, Type};

use crate::addr::AddrClass;
use crate::env::NetEnv;
use crate::local::{IfaceAddr, IfaceKind, RouteSources};
use crate::socket::{BoundSocket, RECV_BUFFER};
use crate::udp::BoundUdp;
use crate::{BoxFuture, NetError};

/// A machine on the loopback interface (design §8.3 `LoopbackNet`): its one
/// address is `127.0.0.x`, reported as a private address of a physical
/// interface with prefix /8, and its session sockets are real UDP sockets
/// bound to that address (IPv4 only). Two values with different `x` are two
/// computers on one LAN. Linux and Windows route all of `127/8` to the
/// loopback interface; macOS has only `127.0.0.1` unless more are aliased
/// (`ifconfig lo0 alias 127.0.0.2`).
#[derive(Debug, Clone, Copy)]
pub struct LoopbackNet {
    ip: Ipv4Addr,
}

impl LoopbackNet {
    /// The machine at `127.0.0.x`.
    #[must_use]
    pub fn new(x: u8) -> Self {
        Self {
            ip: Ipv4Addr::new(127, 0, 0, x),
        }
    }

    /// Its address.
    #[must_use]
    pub fn ip(&self) -> Ipv4Addr {
        self.ip
    }

    /// Its one interface address.
    fn iface(&self) -> IfaceAddr {
        IfaceAddr {
            ip: IpAddr::V4(self.ip),
            prefix_len: 8,
            class: AddrClass::Private,
            temporary: false,
            deprecated: false,
            tentative: false,
            duplicated: false,
            eui64: false,
            iface_index: 1,
            iface_kind: IfaceKind::Physical,
            up: true,
            gateway_v4: None,
        }
    }

    fn bind_once(&self, port: u16) -> io::Result<std::net::UdpSocket> {
        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        let _ = sock.set_recv_buffer_size(RECV_BUFFER);
        sock.set_nonblocking(true)?;
        sock.bind(&SocketAddr::new(IpAddr::V4(self.ip), port).into())?;
        Ok(sock.into())
    }
}

impl NetEnv for LoopbackNet {
    fn interfaces(&self) -> BoxFuture<'static, Result<Vec<IfaceAddr>, NetError>> {
        let iface = self.iface();
        Box::pin(async move { Ok(vec![iface]) })
    }

    fn route_sources(&self) -> RouteSources {
        RouteSources {
            v4: Some(self.ip),
            v6: None,
        }
    }

    /// A real UDP socket on `127.0.0.x:port` (a busy `port` is retried
    /// with any port), under [`QuietUdp`](crate::QuietUdp).
    fn bind(&self, port: Option<u16>) -> io::Result<BoundUdp> {
        let fixed = port.unwrap_or(0);
        let sock = match self.bind_once(fixed) {
            Err(e) if fixed != 0 && e.kind() == io::ErrorKind::AddrInUse => self.bind_once(0),
            other => other,
        }?;
        BoundUdp::quiet(BoundSocket {
            sock,
            dual_stack: false,
        })
    }

    fn admit_loopback(&self) -> bool {
        true
    }
}

/// [`LoopbackNet`] behind the seam, as a link holds it.
#[must_use]
pub fn loopback(x: u8) -> Arc<dyn NetEnv> {
    Arc::new(LoopbackNet::new(x))
}
