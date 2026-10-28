//! UPnP-IGD through igd-next 0.18.0, `aio_tokio` (design `direct` §7.4
//! (b); docs/research/nat-traversal.md §4).
//!
//! - **The search asks the gateway first:** a unicast M-SEARCH to
//!   `(gateway, 1900)` for at most [`UNICAST_WAIT`], so that no other device
//!   on the network learns a session starts and no other responder's
//!   description is fetched; the multicast search to `239.255.255.250:1900`
//!   runs only if the gateway did not answer, for what remains of the
//!   deadline.
//! - **The router found must be the gateway** (`addr.ip() == gateway`),
//!   and igd-next's `allowed_gateway_ips` stays empty, so the device's URLs
//!   must name the responder's own address. igd-next's search ends at the
//!   first device that answers, so on the multicast fallback another UPnP
//!   device answering before the gateway fails the request
//!   ([`MapFail::NoGateway`]) even if the gateway answers later; a gateway
//!   that answers the unicast search never meets this.
//! - **Leases:** 600 s, renewed with `AddPortMapping` again; a router that
//!   grants only permanent mappings (725) gets none, and lease 0 is never
//!   asked for (design §16.3, E7).
//! - A mapping whose external address is not public is removed again.
//! - **A delete names only a mapping of ours** (decision M1-81):
//!   `DeletePortMapping` keys on the external port alone, and an IGDv1
//!   router usually lets any LAN device delete any mapping, so before each
//!   delete the router's table is read (`GetGenericPortMappingEntry` by
//!   index, at most [`TABLE_WALK`] entries; igd-next 0.18 has no
//!   `GetSpecificPortMappingEntry`). The port is deleted when its entry
//!   forwards to this computer's address and port under Tornect's
//!   description, never when it names another computer, port or program,
//!   nor when the table has no entry for it. A router that will not show
//!   its table gets the delete only for a port it granted us within its
//!   lease (a release, a sweep: [`Removal`]), never after an
//!   `AddPortMapping` the deadline cut, whose port may be another
//!   computer's (718).

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use igd_next::aio::Gateway;
use igd_next::aio::tokio::{Tokio, search_gateway};
use igd_next::{
    AddAnyPortError, AddPortError, GatewayIpVersion, GetExternalIpError,
    GetGenericPortMappingEntryError, PortMappingEntry, PortMappingProtocol, RemovePortError,
    RequestError, SearchError, SearchOptions,
};
use tokio::time::Instant;

use super::ledger::{EntryId, LedgerEntry, unix_now};
use super::real::{Ask, Closing, Ctx, Wire};
use super::{MAP_LEASE, MapFail, MapVia, Mapping, MappingHandle};
use crate::BoxFuture;
use crate::addr::{AddrClass, class_v4};

/// A UPnP router found by a search.
pub(super) type Found = Gateway<Tokio>;

/// How long the unicast search waits for the gateway (design §8.5).
pub(super) const UNICAST_WAIT: Duration = Duration::from_millis(600);

/// The description every mapping carries.
const DESCRIPTION: &str = "Tornect";

/// The most entries of a router's table read to find who holds a port
/// before a delete: a home router lists a few, and each read is one HTTP
/// request inside the delete's cap.
pub(super) const TABLE_WALK: u32 = 32;

/// [`MAP_LEASE`] in UPnP's seconds.
const LEASE_SECS: u32 = 600;

const _: () = assert!(LEASE_SECS as u64 == MAP_LEASE.as_secs());

fn options(wire: &Wire, client: Ipv4Addr, to: SocketAddr, wait: Duration) -> SearchOptions {
    let mut opts = SearchOptions::default();
    opts.bind_addr = SocketAddr::new(IpAddr::V4(client), 0);
    opts.broadcast_address = to;
    opts.timeout = Some(wait);
    opts.single_search_timeout = Some(wait);
    opts.gateway_ip_version = GatewayIpVersion::V4;
    opts.allowed_gateway_ips.clone_from(&wire.trusted);
    opts
}

fn search_fail(e: &SearchError) -> MapFail {
    match e {
        SearchError::NoResponseWithinTimeout => MapFail::Timeout,
        SearchError::IoError(_) => MapFail::Io,
        _ => MapFail::NoGateway,
    }
}

/// The router found, if it is the gateway.
fn the_gateway(found: Found, gateway: Ipv4Addr) -> Result<Found, MapFail> {
    if found.addr.ip() == IpAddr::V4(gateway) {
        Ok(found)
    } else {
        Err(MapFail::NoGateway)
    }
}

/// The UPnP router at `gateway`: the unicast search, then the multicast one
/// if the unicast got no answer, until `deadline`. A search creates no
/// router state.
pub(super) async fn search(
    wire: &Wire,
    gateway: Ipv4Addr,
    client: Ipv4Addr,
    deadline: Instant,
) -> Result<Found, MapFail> {
    let first = deadline
        .saturating_duration_since(Instant::now())
        .min(UNICAST_WAIT);
    if first.is_zero() {
        return Err(MapFail::Timeout);
    }
    let unicast = SocketAddr::new(IpAddr::V4(gateway), wire.ssdp_port);
    match search_gateway(options(wire, client, unicast, first)).await {
        Ok(found) => return the_gateway(found, gateway),
        Err(SearchError::NoResponseWithinTimeout) => {}
        Err(e) => return Err(search_fail(&e)),
    }
    let rest = deadline.saturating_duration_since(Instant::now());
    if rest.is_zero() {
        return Err(MapFail::Timeout);
    }
    match search_gateway(options(wire, client, wire.multicast, rest)).await {
        Ok(found) => the_gateway(found, gateway),
        Err(e) => Err(search_fail(&e)),
    }
}

/// The failure a control request's error stands for, and whether the
/// router answered it with a UPnP error code (so that it made no mapping).
fn request_fail(e: &RequestError) -> (MapFail, bool) {
    match e {
        RequestError::ErrorCode(725, _) => (MapFail::PermanentOnly, true),
        RequestError::ErrorCode(..) | RequestError::UnsupportedAction(_) => {
            (MapFail::Refused, true)
        }
        RequestError::InvalidResponse(_) => (MapFail::Refused, false),
        _ => (MapFail::Io, false),
    }
}

fn add_fail(e: &AddPortError) -> (MapFail, bool) {
    match e {
        AddPortError::OnlyPermanentLeasesSupported => (MapFail::PermanentOnly, true),
        AddPortError::RequestError(r) => request_fail(r),
        _ => (MapFail::Refused, true),
    }
}

fn any_fail(e: &AddAnyPortError) -> (MapFail, bool) {
    match e {
        AddAnyPortError::OnlyPermanentLeasesSupported => (MapFail::PermanentOnly, true),
        AddAnyPortError::RequestError(r) => request_fail(r),
        _ => (MapFail::Refused, true),
    }
}

fn external_fail(e: &GetExternalIpError) -> MapFail {
    match e {
        GetExternalIpError::RequestError(r) => request_fail(r).0,
        _ => MapFail::Refused,
    }
}

/// `DeletePortMapping` of `port`; a mapping the router no longer has
/// counts as removed. Called only through [`remove_ours`].
async fn remove(found: &Found, port: u16) -> Result<(), MapFail> {
    match found.remove_port(PortMappingProtocol::UDP, port).await {
        Ok(()) | Err(RemovePortError::NoSuchPortMapping) => Ok(()),
        Err(RemovePortError::RequestError(r)) => Err(request_fail(&r).0),
        Err(_) => Err(MapFail::Refused),
    }
}

/// Who the router's table says holds a UDP external port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Holder {
    /// This computer's address and port, under Tornect's description.
    Ours,
    /// Another computer, port or program.
    Other,
    /// No entry: the table as the router shows it ends without one.
    Nobody,
    /// The router did not say: the action refused, unsupported or failed,
    /// or the port not among the first [`TABLE_WALK`] entries.
    Unknown,
}

/// Whether an entry's remote host is the wildcard, which is what a
/// `DeletePortMapping` with an empty `NewRemoteHost` (igd-next's) deletes
/// and what Tornect's `AddPortMapping` makes.
fn wildcard(remote_host: &str) -> bool {
    let host = remote_host.trim();
    host.is_empty() || host == "*" || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_unspecified())
}

/// Whether `entry` is the wildcard UDP mapping of `port`, and if so whether
/// it forwards to `client:internal_port` under Tornect's description.
fn holder_of(
    entry: &PortMappingEntry,
    port: u16,
    client: Ipv4Addr,
    internal_port: u16,
) -> Option<Holder> {
    if entry.protocol != PortMappingProtocol::UDP
        || entry.external_port != port
        || !wildcard(&entry.remote_host)
    {
        return None;
    }
    let ours = entry.internal_client.trim().parse::<Ipv4Addr>() == Ok(client)
        && entry.internal_port == internal_port
        && entry.port_mapping_description == DESCRIPTION;
    Some(if ours { Holder::Ours } else { Holder::Other })
}

/// Reads the router's table, entry by entry, until the wildcard UDP
/// mapping of `port`. Nothing it reads is logged or kept.
async fn holder(found: &Found, port: u16, client: Ipv4Addr, internal_port: u16) -> Holder {
    for index in 0..TABLE_WALK {
        match found.get_generic_port_mapping_entry(index).await {
            Ok(entry) => {
                if let Some(holder) = holder_of(&entry, port, client, internal_port) {
                    return holder;
                }
            }
            // 713 ends the table; some routers answer 714 there.
            Err(
                GetGenericPortMappingEntryError::SpecifiedArrayIndexInvalid
                | GetGenericPortMappingEntryError::RequestError(RequestError::ErrorCode(714, _)),
            ) => return Holder::Nobody,
            Err(_) => return Holder::Unknown,
        }
    }
    Holder::Unknown
}

/// What a guarded delete did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Removal {
    /// The port was deleted.
    Deleted,
    /// The router's table gives the port to no mapping of ours (another
    /// computer's, or none): nothing was deleted, and nothing of ours is
    /// left there.
    NotOurs,
}

/// Whether a router that does not show its table still gets the delete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Unshown {
    /// The router granted us this port within its lease (a release, a
    /// sweep): delete it.
    Delete,
    /// The port may never have been ours (an `AddPortMapping` the deadline
    /// cut, which the router may have refused with 718): leave it.
    Leave,
}

/// `DeletePortMapping` of `port` only when the router's table says it is
/// the mapping of `client:internal_port` that Tornect made (module docs).
///
/// # Errors
///
/// The delete failed, or the router did not show its table and `unshown`
/// is [`Unshown::Leave`] ([`MapFail::Refused`]).
async fn remove_ours(
    found: &Found,
    port: u16,
    client: Ipv4Addr,
    internal_port: u16,
    unshown: Unshown,
) -> Result<Removal, MapFail> {
    match holder(found, port, client, internal_port).await {
        Holder::Ours => remove(found, port).await.map(|()| Removal::Deleted),
        Holder::Other | Holder::Nobody => Ok(Removal::NotOurs),
        Holder::Unknown => match unshown {
            Unshown::Delete => remove(found, port).await.map(|()| Removal::Deleted),
            Unshown::Leave => Err(MapFail::Refused),
        },
    }
}

/// Removes a UPnP leftover of an earlier run from `found`, if the router's
/// table still gives its port to this computer (a leftover is at most its
/// lease and a minute old, so a router that does not show its table gets
/// the delete).
pub(super) async fn remove_leftover(
    found: &Found,
    entry: &LedgerEntry,
) -> Result<Removal, MapFail> {
    let port = entry.external_port.ok_or(MapFail::Refused)?;
    remove_ours(
        found,
        port,
        entry.client,
        entry.internal_port,
        Unshown::Delete,
    )
    .await
}

/// An `AddPortMapping` (or `AddAnyPortMapping`) in flight. Dropped armed
/// (the deadline, or an error after which the router may hold the
/// mapping), it removes the port asked for, when there is one, in a capped
/// release of its own (design §7.4 "Deadline"): only when the router's
/// table gives that port to this computer's `client:port` under Tornect's
/// description, since a router too slow to answer may have been about to
/// refuse it (718) as another computer's. It forgets the entry once the
/// table shows nothing of ours there. A router that does not show its
/// table gets no delete, and its entry is kept naming no port, as with no
/// port asked for: only the lease bounds the mapping.
struct Adding {
    ctx: Ctx,
    found: Found,
    id: EntryId,
    client: Ipv4Addr,
    port: Option<u16>,
    armed: bool,
}

impl Adding {
    fn new(ctx: &Ctx, found: &Found, id: EntryId, client: Ipv4Addr, port: Option<u16>) -> Self {
        Self {
            ctx: ctx.clone(),
            found: found.clone(),
            id,
            client,
            port,
            armed: true,
        }
    }

    /// The router answered and holds nothing this guard must remove: it
    /// granted the mapping (whose handle owns it now) or the port is
    /// someone else's (718).
    fn made(mut self) {
        self.armed = false;
    }

    /// The router refused: it holds nothing, so the entry goes.
    async fn refused(mut self) {
        self.armed = false;
        self.ctx.remove(self.id).await;
    }
}

impl Drop for Adding {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let Some(port) = self.port else {
            return;
        };
        let ctx = self.ctx.clone();
        let found = self.found.clone();
        let id = self.id;
        let client = self.client;
        self.ctx.spawn(Box::pin(async move {
            // The external port asked for is the internal one.
            if remove_ours(&found, port, client, port, Unshown::Leave)
                .await
                .is_ok()
            {
                ctx.remove(id).await;
            }
        }));
    }
}

/// Maps `ask.port` on the router `found`: `AddPortMapping` for the same
/// external port, `AddAnyPortMapping` when that port is taken (718), never
/// a permanent mapping; then the external address, which must be public.
pub(super) async fn map_on(ctx: &Ctx, found: Found, ask: Ask) -> Result<Mapping, MapFail> {
    let port = ask.port.get();
    let local = SocketAddr::new(IpAddr::V4(ask.client), port);
    // The entry names no port until the router has granted one: a sweep
    // deletes UPnP leftovers by external port, and a port the router
    // refused (718) belongs to someone else.
    let id = ctx
        .add(LedgerEntry {
            via: MapVia::Upnp,
            gateway: ask.gateway,
            client: ask.client,
            internal_port: port,
            external_port: None,
            pcp_nonce: None,
            created: unix_now(),
        })
        .await?;
    let adding = Adding::new(ctx, &found, id, ask.client, Some(port));
    let external_port = match found
        .add_port(
            PortMappingProtocol::UDP,
            port,
            local,
            LEASE_SECS,
            DESCRIPTION,
        )
        .await
    {
        Ok(()) => {
            adding.made();
            port
        }
        Err(AddPortError::PortInUse) => {
            // Nothing was made at `port`; the router picks another, which
            // only its answer names.
            adding.made();
            let any = Adding::new(ctx, &found, id, ask.client, None);
            match found
                .add_any_port(PortMappingProtocol::UDP, local, LEASE_SECS, DESCRIPTION)
                .await
            {
                Ok(granted) => {
                    any.made();
                    granted
                }
                Err(e) => {
                    let (fail, answered) = any_fail(&e);
                    if answered {
                        any.refused().await;
                    }
                    return Err(fail);
                }
            }
        }
        Err(e) => {
            let (fail, answered) = add_fail(&e);
            if answered {
                adding.refused().await;
            }
            return Err(fail);
        }
    };
    let handle = UpnpHandle {
        ctx: ctx.clone(),
        id,
        found: found.clone(),
        local,
        external_port,
    };
    let mut mapping = ctx.made(
        id,
        SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, external_port),
        MapVia::Upnp,
        MAP_LEASE,
        Box::new(handle),
    );
    // From here a drop of `mapping` (the deadline, a private address)
    // releases it on this runtime. A failed write leaves the entry without
    // a port: after a crash the lease alone bounds the mapping.
    let _ = ctx
        .update(id, move |e| e.external_port = Some(external_port))
        .await;
    match found.get_external_ip().await {
        Ok(IpAddr::V4(ip)) if class_v4(ip) == AddrClass::Global => {
            mapping.external = SocketAddrV4::new(ip, external_port);
            Ok(mapping)
        }
        Ok(_) => Err(MapFail::NotGlobal),
        Err(e) => Err(external_fail(&e)),
    }
}

/// A UPnP mapping's renewals and release.
struct UpnpHandle {
    ctx: Ctx,
    id: EntryId,
    found: Found,
    local: SocketAddr,
    external_port: u16,
}

impl MappingHandle for UpnpHandle {
    fn renew(&mut self) -> BoxFuture<'_, Result<Duration, MapFail>> {
        Box::pin(async move {
            self.found
                .add_port(
                    PortMappingProtocol::UDP,
                    self.external_port,
                    self.local,
                    LEASE_SECS,
                    DESCRIPTION,
                )
                .await
                .map_err(|e| add_fail(&e).0)?;
            self.ctx.touch(self.id).await;
            Ok(MAP_LEASE)
        })
    }

    /// Deletes the port if the router's table still gives it to this
    /// mapping (a router that does not show its table gets the delete: it
    /// granted or renewed the port within its lease). A table that gives
    /// it to another computer, or to none, ends the mapping without a
    /// delete: nothing of ours is left there.
    fn release(self: Box<Self>) -> BoxFuture<'static, ()> {
        Box::pin(async move {
            let closing = Closing::new(&self.ctx, self.id, MapVia::Upnp);
            let IpAddr::V4(client) = self.local.ip() else {
                closing.finish(false).await;
                return;
            };
            let removed = remove_ours(
                &self.found,
                self.external_port,
                client,
                self.local.port(),
                Unshown::Delete,
            )
            .await
            .is_ok();
            closing.finish(removed).await;
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(
        remote_host: &str,
        client: &str,
        internal_port: u16,
        description: &str,
    ) -> PortMappingEntry {
        PortMappingEntry {
            remote_host: remote_host.to_owned(),
            external_port: 50_417,
            protocol: PortMappingProtocol::UDP,
            internal_port,
            internal_client: client.to_owned(),
            enabled: true,
            port_mapping_description: description.to_owned(),
            lease_duration: 600,
        }
    }

    const CLIENT: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 20);

    /// Ours is the wildcard UDP mapping of the port to this computer's
    /// address and port under Tornect's description; any other mapping of
    /// the port is another's; a mapping of another port or protocol, or for
    /// one remote host only, is not the one a delete would hit.
    #[test]
    fn only_our_wildcard_udp_mapping_is_ours() {
        let ours = entry("", "192.168.1.20", 50_417, DESCRIPTION);
        assert_eq!(holder_of(&ours, 50_417, CLIENT, 50_417), Some(Holder::Ours));
        for host in ["*", "0.0.0.0", " ", "::"] {
            let e = entry(host, "192.168.1.20", 50_417, DESCRIPTION);
            assert_eq!(
                holder_of(&e, 50_417, CLIENT, 50_417),
                Some(Holder::Ours),
                "{host:?}"
            );
        }
        for (client, port, description) in [
            ("192.168.1.21", 50_417, DESCRIPTION),
            ("192.168.1.20", 50_418, DESCRIPTION),
            ("192.168.1.20", 50_417, "Tornect (old)"),
            ("192.168.1.20", 50_417, "tornect"),
            ("router.lan", 50_417, DESCRIPTION),
            ("", 50_417, DESCRIPTION),
        ] {
            let e = entry("", client, port, description);
            assert_eq!(
                holder_of(&e, 50_417, CLIENT, 50_417),
                Some(Holder::Other),
                "{client} {port} {description}"
            );
        }
        assert_eq!(holder_of(&ours, 50_418, CLIENT, 50_417), None);
        let tcp = PortMappingEntry {
            protocol: PortMappingProtocol::TCP,
            ..entry("", "192.168.1.20", 50_417, DESCRIPTION)
        };
        assert_eq!(holder_of(&tcp, 50_417, CLIENT, 50_417), None);
        let pinned = entry("203.0.113.9", "192.168.1.20", 50_417, DESCRIPTION);
        assert_eq!(holder_of(&pinned, 50_417, CLIENT, 50_417), None);
    }
}
