//! [`RealMapper`]: the router protocols behind [`PortMapper`] (design
//! `direct` §7.4): PCP, then NAT-PMP, through crab_nat ([`super::nat`]) and,
//! at the same time, a UPnP-IGD search through igd-next
//! ([`super::upnp`]); at most one mapping per request, every request
//! written to the [`MappingLedger`] before it is sent, and the start-up
//! [`sweep`](RealMapper::sweep) of what an earlier run left.

use std::fmt;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::num::NonZeroU16;
use std::sync::Arc;
use std::time::Duration;

use tokio::runtime::Handle;

use super::ledger::{EntryId, LEDGER_MAX_AGE, LedgerEntry, MappingLedger, unix_now};
use super::release::ReleaseTracker;
use super::{
    MAP_LEASE, MapEvent, MapEvents, MapFail, MapProtocols, MapRequest, MapVia, Mapping,
    MappingHandle, PortMapper, nat, upnp,
};
use crate::BoxFuture;
use crate::addr::{AddrClass, RedactedIp, class_v4};

/// The longest the start-up sweep runs ([`crate::RealNet::sweep_leftovers`]).
pub const SWEEP_CAP: Duration = Duration::from_secs(5);

/// How old a UPnP leftover may be and still be removed: its lease and a
/// minute. Past it the router has ended the mapping itself, and the
/// external port it named may since belong to another computer on the
/// network, whose mapping a `DeletePortMapping` by port would remove (PCP
/// deletes by nonce and NAT-PMP by this computer's own address, so their
/// leftovers keep [`LEDGER_MAX_AGE`]).
const UPNP_LEFTOVER_MAX_AGE: Duration = Duration::from_secs(MAP_LEASE.as_secs() + 60);

/// How long the sweep searches for the UPnP router.
const SWEEP_SEARCH: Duration = Duration::from_millis(1500);

/// The router this computer uses now: the IPv4 default gateway of the
/// route-source interface, and the route source. The sweep contacts no
/// other.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Router {
    /// The default gateway.
    pub gateway: Ipv4Addr,
    /// This computer's address toward it.
    pub client: Ipv4Addr,
}

impl fmt::Debug for Router {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Router")
            .field("gateway", &RedactedIp(IpAddr::V4(self.gateway)))
            .field("client", &RedactedIp(IpAddr::V4(self.client)))
            .finish()
    }
}

/// What a sweep did, in counts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// Leftovers removed from the router (each a `LeftoverRemoved` event).
    pub removed: usize,
    /// Leftovers of another router or address, kept for a later start.
    pub kept: usize,
    /// Leftovers too old to act on, unreadable, or of a UPnP request whose
    /// port was never learnt: forgotten without contacting a router.
    pub dropped: usize,
    /// Leftovers whose removal failed, kept for a later start.
    pub failed: usize,
}

/// Where the router protocols send. Production uses the protocols' own
/// ports and trusts only the responder; this crate's tests point them at
/// the fakes on loopback addresses.
#[derive(Clone)]
pub(super) struct Wire {
    /// The UDP port of the unicast SSDP search on the gateway.
    pub ssdp_port: u16,
    /// Where the multicast search goes.
    pub multicast: SocketAddr,
    /// igd-next's `allowed_gateway_ips`: empty in production, so that a
    /// device's URLs must name the responder's own address.
    pub trusted: Vec<IpAddr>,
    /// Whether a loopback gateway and client pass the preconditions.
    pub admit_loopback: bool,
}

impl Wire {
    fn real() -> Self {
        Self {
            ssdp_port: 1900,
            multicast: SocketAddr::from((Ipv4Addr::new(239, 255, 255, 250), 1900)),
            trusted: Vec::new(),
            admit_loopback: false,
        }
    }
}

pub(super) struct Inner {
    ledger: MappingLedger,
    events: Arc<dyn MapEvents>,
    releases: ReleaseTracker,
    pub wire: Wire,
}

/// The router protocols of the real machine. Clones share the ledger, the
/// event sink and the release tracker.
#[derive(Clone)]
pub struct RealMapper {
    inner: Arc<Inner>,
}

impl fmt::Debug for RealMapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealMapper")
            .field("ledger", &self.inner.ledger)
            .field("releases", &self.inner.releases)
            .finish_non_exhaustive()
    }
}

/// What one request asks, copied out of the [`MapRequest`].
#[derive(Clone, Copy)]
pub(super) struct Ask {
    pub gateway: Ipv4Addr,
    pub client: Ipv4Addr,
    pub port: NonZeroU16,
    pub protocols: MapProtocols,
}

/// One request's view of the mapper: the shared parts and the runtime the
/// request runs on, where its mappings release themselves.
#[derive(Clone)]
pub(super) struct Ctx {
    pub inner: Arc<Inner>,
    rt: Option<Handle>,
}

impl Ctx {
    fn current(inner: &Arc<Inner>) -> Self {
        Self {
            inner: Arc::clone(inner),
            rt: Handle::try_current().ok(),
        }
    }

    /// Records an entry before its request is sent.
    pub async fn add(&self, entry: LedgerEntry) -> Result<EntryId, MapFail> {
        let ledger = self.inner.ledger.clone();
        tokio::task::spawn_blocking(move || ledger.add(entry))
            .await
            .map_err(|_| MapFail::Io)?
            .map_err(|_| MapFail::Io)
    }

    /// Changes an entry and writes the list.
    pub async fn update(
        &self,
        id: EntryId,
        change: impl FnOnce(&mut LedgerEntry) + Send + 'static,
    ) -> Result<(), MapFail> {
        let ledger = self.inner.ledger.clone();
        tokio::task::spawn_blocking(move || ledger.update(id, change))
            .await
            .map_err(|_| MapFail::Io)?
            .map_err(|_| MapFail::Io)
    }

    /// Marks an entry asked for now (a renewal), so that a long session's
    /// leftover is not taken for a stale one.
    pub async fn touch(&self, id: EntryId) {
        let now = unix_now();
        let _ = self.update(id, move |e| e.created = now).await;
    }

    /// Forgets an entry whose mapping is gone or was never made.
    pub async fn remove(&self, id: EntryId) {
        let ledger = self.inner.ledger.clone();
        let _ = tokio::task::spawn_blocking(move || ledger.remove(id)).await;
    }

    /// Marks an entry as backing no mapping held now (memory only).
    pub fn not_live(&self, id: EntryId) {
        self.inner.ledger.set_live(id, false);
    }

    pub fn emit(&self, ev: MapEvent) {
        self.inner.events.on_event(ev);
    }

    /// Runs `fut` as a counted, capped release on this request's runtime.
    pub fn spawn(&self, fut: BoxFuture<'static, ()>) {
        if let Some(rt) = self.rt.clone().or_else(|| Handle::try_current().ok()) {
            self.inner.releases.spawn(&rt, fut);
        }
    }

    /// The mapping the router just granted: its entry live, `Opened`
    /// reported, released on drop from here on.
    pub fn made(
        &self,
        id: EntryId,
        external: SocketAddrV4,
        via: MapVia,
        granted: Duration,
        handle: Box<dyn MappingHandle>,
    ) -> Mapping {
        self.inner.ledger.set_live(id, true);
        self.emit(MapEvent::Opened(via));
        Mapping::new(external, via, granted, handle)
            .release_on_drop(self.rt.clone(), self.inner.releases.clone())
    }
}

/// The end of one release: `Closed` and the entry forgotten when the
/// router removed the mapping, `CloseFailed` and the entry kept for the
/// next start otherwise, and `CloseFailed` too when the release is cut
/// short (its cap, a runtime shutting down).
pub(super) struct Closing {
    ctx: Ctx,
    id: EntryId,
    via: MapVia,
    done: bool,
}

impl Closing {
    pub fn new(ctx: &Ctx, id: EntryId, via: MapVia) -> Self {
        Self {
            ctx: ctx.clone(),
            id,
            via,
            done: false,
        }
    }

    pub async fn finish(mut self, removed: bool) {
        self.done = true;
        if removed {
            self.ctx.emit(MapEvent::Closed(self.via));
            self.ctx.remove(self.id).await;
        } else {
            self.ctx.not_live(self.id);
            self.ctx.emit(MapEvent::CloseFailed(self.via));
        }
    }
}

impl Drop for Closing {
    fn drop(&mut self) {
        if !self.done {
            self.ctx.not_live(self.id);
            self.ctx.emit(MapEvent::CloseFailed(self.via));
        }
    }
}

/// The more telling of two failures, for the one a request reports:
/// `PermanentOnly`, then `NotGlobal`, `Refused`, `Timeout`, `Io`, and
/// `NoGateway` (a protocol that was off) last.
fn worse(a: MapFail, b: MapFail) -> MapFail {
    fn rank(f: MapFail) -> u8 {
        match f {
            MapFail::PermanentOnly => 5,
            MapFail::NotGlobal => 4,
            MapFail::Refused => 3,
            MapFail::Timeout => 2,
            MapFail::Io => 1,
            MapFail::NoGateway => 0,
        }
    }
    if rank(b) > rank(a) { b } else { a }
}

/// What the sweep does with one leftover.
#[derive(Debug, PartialEq, Eq)]
enum Leftward {
    Remove,
    Keep,
    Forget,
}

fn leftover_action(entry: &LedgerEntry, here: Option<Router>, now: u64) -> Leftward {
    let age = now.saturating_sub(entry.created);
    if age > LEDGER_MAX_AGE.as_secs() {
        return Leftward::Forget;
    }
    if entry.via == MapVia::Upnp
        && (entry.external_port.is_none() || age > UPNP_LEFTOVER_MAX_AGE.as_secs())
    {
        return Leftward::Forget;
    }
    let ours = Router {
        gateway: entry.gateway,
        client: entry.client,
    };
    if here == Some(ours) {
        Leftward::Remove
    } else {
        Leftward::Keep
    }
}

impl RealMapper {
    /// A mapper that records its requests in `ledger`, reports to `events`
    /// and releases dropped mappings through `releases`.
    #[must_use]
    pub fn new(
        ledger: MappingLedger,
        events: Arc<dyn MapEvents>,
        releases: ReleaseTracker,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                ledger,
                events,
                releases,
                wire: Wire::real(),
            }),
        }
    }

    /// The mapper pointed at fake routers on loopback addresses: the unicast
    /// SSDP search goes to `ssdp_port` on the gateway, the multicast one to
    /// `multicast`, the device URLs may name `trusted`, and a loopback
    /// gateway and client pass the preconditions. PCP and NAT-PMP keep
    /// their fixed port 5351.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn on_loopback(self, ssdp_port: u16, multicast: SocketAddr, trusted: Vec<IpAddr>) -> Self {
        let inner = &self.inner;
        Self {
            inner: Arc::new(Inner {
                ledger: inner.ledger.clone(),
                events: Arc::clone(&inner.events),
                releases: inner.releases.clone(),
                wire: Wire {
                    ssdp_port,
                    multicast,
                    trusted,
                    admit_loopback: true,
                },
            }),
        }
    }

    /// The ledger.
    #[must_use]
    pub fn ledger(&self) -> &MappingLedger {
        &self.inner.ledger
    }

    /// The release tracker.
    #[must_use]
    pub fn releases(&self) -> &ReleaseTracker {
        &self.inner.releases
    }

    fn usable(&self, ip: Ipv4Addr) -> bool {
        matches!(class_v4(ip), AddrClass::Private | AddrClass::SharedCgnat)
            || (self.inner.wire.admit_loopback && ip.is_loopback())
    }

    /// Removes what dead processes left in the ledger's directory (design
    /// §7.4 "Sweep at start"): each leftover of the router `here` resolves
    /// to is deleted from it, reported as `LeftoverRemoved`; a leftover of
    /// another router or address is kept for a later start (no other router
    /// is contacted); one older than [`LEDGER_MAX_AGE`] (a UPnP one: than
    /// its lease and a minute), or a UPnP one whose port was never learnt,
    /// is forgotten. `here` is awaited only when there are leftovers. A
    /// protocol whose router does not answer one removal is not asked for
    /// the rest. The caller bounds the call ([`SWEEP_CAP`]).
    pub async fn sweep(&self, here: impl Future<Output = Option<Router>>) -> SweepReport {
        let ledger = self.inner.ledger.clone();
        let Ok(leftovers) = tokio::task::spawn_blocking(move || ledger.take_leftovers()).await
        else {
            return SweepReport::default();
        };
        let mut report = SweepReport::default();
        let here = if leftovers.iter().any(|l| !l.entries.is_empty()) {
            here.await
        } else {
            None
        };
        let now = unix_now();
        let mut silent: Vec<MapVia> = Vec::new();
        let mut upnp_router: Option<Option<upnp::Found>> = None;
        for left in leftovers {
            report.dropped += left.unreadable;
            let mut kept = Vec::new();
            for entry in &left.entries {
                match leftover_action(entry, here, now) {
                    Leftward::Forget => {
                        report.dropped += 1;
                        continue;
                    }
                    Leftward::Keep => {
                        report.kept += 1;
                        kept.push(entry.clone());
                        continue;
                    }
                    Leftward::Remove => {}
                }
                let result = if silent.contains(&entry.via) {
                    Err(MapFail::Timeout)
                } else if entry.via == MapVia::Upnp {
                    if upnp_router.is_none() {
                        let deadline = tokio::time::Instant::now() + SWEEP_SEARCH;
                        upnp_router = Some(
                            upnp::search(&self.inner.wire, entry.gateway, entry.client, deadline)
                                .await
                                .ok(),
                        );
                    }
                    match upnp_router.as_ref().and_then(Option::as_ref) {
                        Some(found) => upnp::remove_leftover(found, entry).await,
                        None => Err(MapFail::NoGateway),
                    }
                } else {
                    nat::remove_leftover(entry).await
                };
                match result {
                    Ok(()) => {
                        report.removed += 1;
                        self.inner
                            .events
                            .on_event(MapEvent::LeftoverRemoved(entry.via));
                    }
                    Err(fail) => {
                        report.failed += 1;
                        kept.push(entry.clone());
                        if matches!(fail, MapFail::Timeout | MapFail::Io | MapFail::NoGateway)
                            && !silent.contains(&entry.via)
                        {
                            silent.push(entry.via);
                        }
                    }
                }
            }
            let _ = tokio::task::spawn_blocking(move || left.finish(&kept)).await;
        }
        report
    }

    async fn map_now(self, req: MapRequest) -> Result<Mapping, MapFail> {
        if !req.protocols.any() || !self.usable(req.gateway) || !self.usable(req.client) {
            return Err(MapFail::NoGateway);
        }
        let ctx = Ctx::current(&self.inner);
        let ask = Ask {
            gateway: req.gateway,
            client: req.client,
            port: req.internal_port,
            protocols: req.protocols,
        };
        let deadline = tokio::time::Instant::from_std(req.deadline);
        let work = async {
            let nat_on = ask.protocols.pcp || ask.protocols.nat_pmp;
            let nat = async {
                if nat_on {
                    nat::map(&ctx, ask).await
                } else {
                    Err(MapFail::NoGateway)
                }
            };
            let search = async {
                if ask.protocols.upnp {
                    upnp::search(&ctx.inner.wire, ask.gateway, ask.client, deadline).await
                } else {
                    Err(MapFail::NoGateway)
                }
            };
            tokio::pin!(nat, search);
            let mut nat_fail = None;
            let mut found = None;
            while nat_fail.is_none() || found.is_none() {
                tokio::select! {
                    done = &mut nat, if nat_fail.is_none() => match done {
                        Ok(mapping) => return Ok(mapping),
                        // The router's own address is not public: a UPnP
                        // mapping on it would not help either.
                        Err(MapFail::NotGlobal) => return Err(MapFail::NotGlobal),
                        Err(fail) => nat_fail = Some(fail),
                    },
                    done = &mut search, if found.is_none() => found = Some(done),
                }
            }
            let nat_fail = nat_fail.unwrap_or(MapFail::NoGateway);
            match found {
                Some(Ok(router)) => upnp::map_on(&ctx, router, ask)
                    .await
                    .map_err(|fail| worse(nat_fail, fail)),
                Some(Err(fail)) => Err(worse(nat_fail, fail)),
                None => Err(nat_fail),
            }
        };
        tokio::time::timeout_at(deadline, work)
            .await
            .unwrap_or(Err(MapFail::Timeout))
    }
}

impl PortMapper for RealMapper {
    /// Asks the gateway for `req.internal_port` (design §7.4 "`RealMapper::
    /// map`"): nothing is sent unless a protocol is on and the gateway and
    /// the client are private or shared (CGNAT) addresses. PCP (falling back
    /// to NAT-PMP on a router that answers only that) and the UPnP search
    /// run at once; a PCP or NAT-PMP mapping with a public address wins at
    /// once, and only without one does the UPnP router found get an
    /// `AddPortMapping`. A mapping whose external address is not public is
    /// released and the request fails with [`MapFail::NotGlobal`]. The whole
    /// call ends by `req.deadline`.
    fn map(&self, req: MapRequest) -> BoxFuture<'static, Result<Mapping, MapFail>> {
        Box::pin(self.clone().map_now(req))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(via: MapVia, created: u64) -> LedgerEntry {
        LedgerEntry {
            via,
            gateway: Ipv4Addr::new(192, 168, 1, 1),
            client: Ipv4Addr::new(192, 168, 1, 20),
            internal_port: 50_000,
            external_port: Some(50_000),
            pcp_nonce: (via == MapVia::Pcp).then_some([1, 2, 3]),
            created,
        }
    }

    #[test]
    fn the_worse_failure_is_reported() {
        assert_eq!(
            worse(MapFail::Timeout, MapFail::PermanentOnly),
            MapFail::PermanentOnly
        );
        assert_eq!(worse(MapFail::Refused, MapFail::Timeout), MapFail::Refused);
        assert_eq!(worse(MapFail::NoGateway, MapFail::Io), MapFail::Io);
        assert_eq!(
            worse(MapFail::Timeout, MapFail::NoGateway),
            MapFail::Timeout
        );
        assert_eq!(
            worse(MapFail::NotGlobal, MapFail::Refused),
            MapFail::NotGlobal
        );
    }

    /// Only the router in use now is contacted; age bounds every protocol,
    /// and UPnP's lease bounds its own leftovers.
    #[test]
    fn leftovers_are_removed_only_from_the_router_in_use() {
        let now = 1_700_000_000;
        let here = Some(Router {
            gateway: Ipv4Addr::new(192, 168, 1, 1),
            client: Ipv4Addr::new(192, 168, 1, 20),
        });
        for via in [MapVia::Pcp, MapVia::NatPmp, MapVia::Upnp] {
            assert_eq!(
                leftover_action(&entry(via, now - 10), here, now),
                Leftward::Remove
            );
            assert_eq!(
                leftover_action(&entry(via, now - 10), None, now),
                Leftward::Keep
            );
            let elsewhere = Some(Router {
                gateway: Ipv4Addr::new(10, 0, 0, 1),
                client: Ipv4Addr::new(192, 168, 1, 20),
            });
            assert_eq!(
                leftover_action(&entry(via, now - 10), elsewhere, now),
                Leftward::Keep
            );
            let moved = Some(Router {
                gateway: Ipv4Addr::new(192, 168, 1, 1),
                client: Ipv4Addr::new(192, 168, 1, 21),
            });
            assert_eq!(
                leftover_action(&entry(via, now - 10), moved, now),
                Leftward::Keep
            );
            let day = LEDGER_MAX_AGE.as_secs();
            assert_eq!(
                leftover_action(&entry(via, now - day - 1), here, now),
                Leftward::Forget
            );
        }
        let hour = entry(MapVia::Pcp, now - 3600);
        assert_eq!(leftover_action(&hour, here, now), Leftward::Remove);
        let hour = entry(MapVia::Upnp, now - 3600);
        assert_eq!(leftover_action(&hour, here, now), Leftward::Forget);
        let mut unknown = entry(MapVia::Upnp, now - 10);
        unknown.external_port = None;
        assert_eq!(leftover_action(&unknown, here, now), Leftward::Forget);
    }
}
