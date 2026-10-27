//! PCP (RFC 6887) and NAT-PMP (RFC 6886) through crab_nat 0.8.1 (design
//! `direct` §7.4 (a); docs/research/nat-traversal.md §3).
//!
//! - **Our own nonce.** Every PCP request carries a nonce from `getrandom`,
//!   written to the ledger before the request, so that a crash still leaves
//!   what a deletion must name (RFC 6887 §11.1, §15).
//! - **Renewal** asks for [`MAP_LEASE`] again, never what the router granted
//!   last: crab_nat's own `PortMapping::renew` re-requests the granted
//!   lifetime, so a short grant would never grow back.
//! - **Deletion** always names the port: `natpmp::try_drop_mapping` with no
//!   port deletes every mapping of this computer.
//! - crab_nat sends from a fresh `0.0.0.0:0` socket `connect`ed to
//!   `gateway:5351`, so the kernel accepts answers from the gateway only.

use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::num::NonZeroU16;
use std::time::Duration;

use crab_nat::{
    InternetProtocol, PortMappingOptions, PortMappingType, TimeoutConfig, VersionCode, natpmp, pcp,
};

use super::ledger::{EntryId, LedgerEntry, unix_now};
use super::real::{Ask, Closing, Ctx};
use super::{MAP_LEASE, MapFail, MapVia, Mapping, MappingHandle};
use crate::BoxFuture;
use crate::addr::{AddrClass, class_v4};

/// crab_nat's retries (design §8.5): a first wait of 250 ms and one retry of
/// at most 500 ms, so a silent router costs well under a second.
pub(super) const TIMEOUTS: TimeoutConfig = TimeoutConfig {
    initial_timeout: Duration::from_millis(250),
    max_retries: 1,
    max_retry_timeout: Some(Duration::from_millis(500)),
};

/// [`MAP_LEASE`] in the protocols' seconds.
const LEASE_SECS: u32 = 600;

const _: () = assert!(LEASE_SECS as u64 == MAP_LEASE.as_secs());

fn options(external_port: NonZeroU16) -> PortMappingOptions {
    PortMappingOptions {
        external_port: Some(external_port),
        lifetime_seconds: Some(LEASE_SECS),
        timeout_config: Some(TIMEOUTS),
    }
}

/// The failure a PCP error stands for, and whether the router answered it
/// with a result (so that it made no mapping). A connection refused (an
/// ICMP port unreachable from the gateway) is an answer too: nothing
/// listens on the PCP port.
fn pcp_fail(e: &pcp::Failure) -> (MapFail, bool) {
    match e {
        pcp::Failure::Timeout => (MapFail::Timeout, false),
        pcp::Failure::Socket(io) => (
            MapFail::Io,
            io.kind() == std::io::ErrorKind::ConnectionRefused,
        ),
        pcp::Failure::Nonce | pcp::Failure::InvalidResponse(_) => (MapFail::Refused, false),
        _ => (MapFail::Refused, true),
    }
}

/// [`pcp_fail`] for NAT-PMP.
fn natpmp_fail(e: &natpmp::Failure) -> (MapFail, bool) {
    match e {
        natpmp::Failure::Timeout => (MapFail::Timeout, false),
        natpmp::Failure::Socket(io) => (
            MapFail::Io,
            io.kind() == std::io::ErrorKind::ConnectionRefused,
        ),
        natpmp::Failure::InvalidResponse(_) => (MapFail::Refused, false),
        _ => (MapFail::Refused, true),
    }
}

fn nonce() -> Result<pcp::Nonce, MapFail> {
    let mut bytes = [0_u8; 12];
    getrandom::fill(&mut bytes).map_err(|_| MapFail::Io)?;
    let word = |i: usize| u32::from_be_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
    Ok([word(0), word(4), word(8)])
}

fn secs(lifetime: u32) -> Duration {
    Duration::from_secs(u64::from(lifetime))
}

/// Why PCP gave no mapping.
enum PcpEnd {
    /// The router speaks NAT-PMP only.
    NatPmpOnly,
    Fail(MapFail),
}

/// PCP, then NAT-PMP where the router answered PCP with "NAT-PMP only"
/// and NAT-PMP is on; NAT-PMP alone when PCP is off.
pub(super) async fn map(ctx: &Ctx, ask: Ask) -> Result<Mapping, MapFail> {
    if ask.protocols.pcp {
        match map_pcp(ctx, ask).await {
            Ok(mapping) => return Ok(mapping),
            Err(PcpEnd::Fail(fail)) => return Err(fail),
            Err(PcpEnd::NatPmpOnly) if !ask.protocols.nat_pmp => return Err(MapFail::Refused),
            Err(PcpEnd::NatPmpOnly) => {}
        }
    } else if !ask.protocols.nat_pmp {
        return Err(MapFail::NoGateway);
    }
    map_natpmp(ctx, ask).await
}

async fn map_pcp(ctx: &Ctx, ask: Ask) -> Result<Mapping, PcpEnd> {
    let nonce = nonce().map_err(PcpEnd::Fail)?;
    let id = ctx
        .add(LedgerEntry {
            via: MapVia::Pcp,
            gateway: ask.gateway,
            client: ask.client,
            internal_port: ask.port.get(),
            external_port: None,
            pcp_nonce: Some(nonce),
            created: unix_now(),
        })
        .await
        .map_err(PcpEnd::Fail)?;
    let base = pcp::BaseMapRequest::new(
        ask.gateway.into(),
        ask.client.into(),
        InternetProtocol::Udp,
        ask.port,
    );
    // A request that times out, or is cut by the deadline, leaves its entry
    // for the next start's sweep (design §7.4 "Deadline").
    match pcp::port_mapping(base, Some(nonce), None, options(ask.port)).await {
        Ok(granted) => {
            let external_ip = match granted.mapping_type() {
                PortMappingType::Pcp { external_ip, .. } => external_ip,
                PortMappingType::NatPmp => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            };
            let external_v4 = match external_ip {
                IpAddr::V4(v4) => v4,
                IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
            };
            let handle = NatHandle {
                ctx: ctx.clone(),
                id,
                via: MapVia::Pcp,
                ask,
                external_port: granted.external_port(),
                nonce: Some(nonce),
                external_ip,
            };
            let mapping = ctx.made(
                id,
                SocketAddrV4::new(external_v4, granted.external_port().get()),
                MapVia::Pcp,
                secs(granted.lifetime()),
                Box::new(handle),
            );
            if class_v4(external_v4) == AddrClass::Global {
                Ok(mapping)
            } else {
                // Dropped: released on this runtime.
                Err(PcpEnd::Fail(MapFail::NotGlobal))
            }
        }
        Err(pcp::Failure::UnsupportedVersion(VersionCode::NatPmp)) => {
            ctx.remove(id).await;
            Err(PcpEnd::NatPmpOnly)
        }
        Err(e) => {
            let (fail, answered) = pcp_fail(&e);
            if answered {
                ctx.remove(id).await;
            }
            Err(PcpEnd::Fail(fail))
        }
    }
}

/// NAT-PMP: the router's external address first, so that a router whose
/// own address is not public is asked for no mapping at all, then the
/// mapping.
async fn map_natpmp(ctx: &Ctx, ask: Ask) -> Result<Mapping, MapFail> {
    let external = natpmp::external_address(ask.gateway.into(), Some(TIMEOUTS))
        .await
        .map_err(|e| natpmp_fail(&e).0)?;
    if class_v4(external) != AddrClass::Global {
        return Err(MapFail::NotGlobal);
    }
    let id = ctx
        .add(LedgerEntry {
            via: MapVia::NatPmp,
            gateway: ask.gateway,
            client: ask.client,
            internal_port: ask.port.get(),
            external_port: None,
            pcp_nonce: None,
            created: unix_now(),
        })
        .await?;
    match natpmp::port_mapping(
        ask.gateway.into(),
        InternetProtocol::Udp,
        ask.port,
        options(ask.port),
    )
    .await
    {
        Ok(granted) => {
            let handle = NatHandle {
                ctx: ctx.clone(),
                id,
                via: MapVia::NatPmp,
                ask,
                external_port: granted.external_port(),
                nonce: None,
                external_ip: IpAddr::V4(external),
            };
            Ok(ctx.made(
                id,
                SocketAddrV4::new(external, granted.external_port().get()),
                MapVia::NatPmp,
                secs(granted.lifetime()),
                Box::new(handle),
            ))
        }
        Err(e) => {
            let (fail, answered) = natpmp_fail(&e);
            if answered {
                ctx.remove(id).await;
            }
            Err(fail)
        }
    }
}

/// Deletes one PCP or NAT-PMP mapping, by its nonce or this computer's
/// internal port.
async fn delete(
    via: MapVia,
    gateway: Ipv4Addr,
    client: Ipv4Addr,
    port: NonZeroU16,
    nonce: Option<pcp::Nonce>,
) -> Result<(), MapFail> {
    match (via, nonce) {
        (MapVia::Pcp, Some(nonce)) => pcp::try_drop_mapping(
            gateway.into(),
            client.into(),
            nonce,
            pcp::DropMappingRange::Single {
                protocol: InternetProtocol::Udp,
                internal_port: port,
            },
            Some(TIMEOUTS),
        )
        .await
        .map_err(|e| pcp_fail(&e).0),
        (MapVia::NatPmp, _) => natpmp::try_drop_mapping(
            gateway.into(),
            InternetProtocol::Udp,
            Some(port),
            Some(TIMEOUTS),
        )
        .await
        .map_err(|e| natpmp_fail(&e).0),
        _ => Err(MapFail::Refused),
    }
}

/// Removes a PCP or NAT-PMP leftover of an earlier run.
pub(super) async fn remove_leftover(entry: &LedgerEntry) -> Result<(), MapFail> {
    let port = NonZeroU16::new(entry.internal_port).ok_or(MapFail::Refused)?;
    delete(
        entry.via,
        entry.gateway,
        entry.client,
        port,
        entry.pcp_nonce,
    )
    .await
}

/// A PCP or NAT-PMP mapping's renewals and release.
struct NatHandle {
    ctx: Ctx,
    id: EntryId,
    via: MapVia,
    ask: Ask,
    external_port: NonZeroU16,
    nonce: Option<pcp::Nonce>,
    external_ip: IpAddr,
}

impl MappingHandle for NatHandle {
    fn renew(&mut self) -> BoxFuture<'_, Result<Duration, MapFail>> {
        Box::pin(async move {
            let opts = options(self.external_port);
            let lifetime = match (self.via, self.nonce) {
                (MapVia::Pcp, Some(nonce)) => {
                    let base = pcp::BaseMapRequest::new(
                        self.ask.gateway.into(),
                        self.ask.client.into(),
                        InternetProtocol::Udp,
                        self.ask.port,
                    );
                    pcp::port_mapping(base, Some(nonce), Some(self.external_ip), opts)
                        .await
                        .map_err(|e| pcp_fail(&e).0)?
                        .lifetime()
                }
                _ => natpmp::port_mapping(
                    self.ask.gateway.into(),
                    InternetProtocol::Udp,
                    self.ask.port,
                    opts,
                )
                .await
                .map_err(|e| natpmp_fail(&e).0)?
                .lifetime(),
            };
            self.ctx.touch(self.id).await;
            Ok(secs(lifetime))
        })
    }

    fn release(self: Box<Self>) -> BoxFuture<'static, ()> {
        Box::pin(async move {
            let closing = Closing::new(&self.ctx, self.id, self.via);
            let removed = delete(
                self.via,
                self.ask.gateway,
                self.ask.client,
                self.ask.port,
                self.nonce,
            )
            .await
            .is_ok();
            closing.finish(removed).await;
        })
    }
}
