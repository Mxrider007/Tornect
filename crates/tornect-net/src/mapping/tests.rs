use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use super::*;

fn request() -> MapRequest {
    MapRequest {
        gateway: Ipv4Addr::new(192, 168, 77, 1),
        client: Ipv4Addr::new(192, 168, 77, 203),
        internal_port: NonZeroU16::new(50_417).unwrap(),
        lease: MAP_LEASE,
        protocols: MapProtocols::ALL,
        deadline: Instant::now() + Duration::from_millis(1500),
    }
}

/// A handle that grants `grants` in turn and counts its releases.
struct Scripted {
    grants: Vec<Result<Duration, MapFail>>,
    released: Arc<AtomicUsize>,
}

impl MappingHandle for Scripted {
    fn renew(&mut self) -> BoxFuture<'_, Result<Duration, MapFail>> {
        let next = self.grants.remove(0);
        Box::pin(async move { next })
    }

    fn release(self: Box<Self>) -> BoxFuture<'static, ()> {
        let released = Arc::clone(&self.released);
        Box::pin(async move {
            released.fetch_add(1, Ordering::SeqCst);
        })
    }
}

#[tokio::test]
async fn no_mapper_answers_no_gateway() {
    let mapper: Arc<dyn PortMapper> = Arc::new(NoMapper);
    assert_eq!(
        mapper.map(request()).await.expect_err("no router"),
        MapFail::NoGateway
    );
}

/// A renewal's grant replaces the last one; a failed renewal keeps it;
/// the release runs only when its future does, after the mapping is
/// gone.
#[tokio::test]
async fn a_mapping_renews_through_its_handle_and_releases_once() {
    let released = Arc::new(AtomicUsize::new(0));
    let mut mapping = Mapping::new(
        SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 50_417),
        MapVia::Pcp,
        Duration::from_secs(120),
        Box::new(Scripted {
            grants: vec![Ok(MAP_LEASE), Err(MapFail::Timeout)],
            released: Arc::clone(&released),
        }),
    );
    assert_eq!(mapping.renew().await, Ok(MAP_LEASE));
    assert_eq!(mapping.granted, MAP_LEASE);
    assert_eq!(mapping.renew().await, Err(MapFail::Timeout));
    assert_eq!(mapping.granted, MAP_LEASE);
    let release = mapping.release();
    assert_eq!(released.load(Ordering::SeqCst), 0);
    release.await;
    assert_eq!(released.load(Ordering::SeqCst), 1);
}

#[test]
fn events_become_router_port_lines_with_the_protocol_only() {
    for (event, line) in [
        (MapEvent::Opened(MapVia::Pcp), "opened pcp"),
        (MapEvent::Closed(MapVia::NatPmp), "closed nat-pmp"),
        (MapEvent::CloseFailed(MapVia::Upnp), "close-failed upnp"),
        (
            MapEvent::LeftoverRemoved(MapVia::Pcp),
            "leftover-removed pcp",
        ),
    ] {
        assert_eq!(event.router_port().detail(), line);
    }
}

#[test]
fn protocols_any() {
    assert!(!MapProtocols::NONE.any());
    assert!(MapProtocols::ALL.any());
    assert!(
        MapProtocols {
            nat_pmp: true,
            ..MapProtocols::NONE
        }
        .any()
    );
    assert_eq!(MapProtocols::default(), MapProtocols::NONE);
}

/// Decision M1-83: neither a request nor a mapping prints an address
/// or a port, and no failure names one.
#[test]
fn no_debug_or_message_prints_an_address_or_a_port() {
    let mapping = Mapping::new(
        SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 50_417),
        MapVia::Upnp,
        MAP_LEASE,
        Box::new(Scripted {
            grants: Vec::new(),
            released: Arc::default(),
        }),
    );
    let mut text = format!("{:?} {:#?} {mapping:?} {mapping:#?}", request(), request());
    for fail in [
        MapFail::NoGateway,
        MapFail::Timeout,
        MapFail::Refused,
        MapFail::PermanentOnly,
        MapFail::NotGlobal,
        MapFail::Io,
    ] {
        text.push_str(&format!(" {fail} {fail:?}"));
    }
    for piece in ["192", "168", "77", "203", "113", "50417", "50_417"] {
        assert!(!text.contains(piece), "\"{piece}\" in {text}");
    }
    for said in ["v4 private", "v4 unusable", "Upnp", "600s"] {
        assert!(text.contains(said), "\"{said}\" missing in {text}");
    }
}

/// Renewal fires at half the grant, within 30 s and 300 s.
#[test]
fn renewal_waits_half_the_grant_within_bounds() {
    let s = Duration::from_secs;
    assert_eq!(renewal_delay(s(120)), s(60));
    assert_eq!(renewal_delay(s(600)), s(300));
    assert_eq!(renewal_delay(s(7200)), s(300));
    assert_eq!(renewal_delay(s(40)), s(30));
    assert_eq!(renewal_delay(Duration::ZERO), s(30));
}

/// A handle that records when each renewal was asked for.
struct Timed {
    grants: Vec<Result<Duration, MapFail>>,
    asked: Arc<Mutex<Vec<Duration>>>,
    start: tokio::time::Instant,
}

impl MappingHandle for Timed {
    fn renew(&mut self) -> BoxFuture<'_, Result<Duration, MapFail>> {
        self.asked.lock().unwrap().push(self.start.elapsed());
        let next = if self.grants.is_empty() {
            Ok(MAP_LEASE)
        } else {
            self.grants.remove(0)
        };
        Box::pin(async move { next })
    }

    fn release(self: Box<Self>) -> BoxFuture<'static, ()> {
        Box::pin(async {})
    }
}

/// Design §12.2: a 120 s grant renews at 60 s; a 600 s grant 300 s later;
/// a failed renewal is tried again 30 s later; the mapping never lapses.
#[tokio::test(start_paused = true)]
async fn keep_renewed_follows_each_grant() {
    let asked = Arc::new(Mutex::new(Vec::new()));
    let start = tokio::time::Instant::now();
    let mut mapping = Mapping::new(
        SocketAddrV4::new(Ipv4Addr::new(64, 0, 0, 9), 50_417),
        MapVia::Pcp,
        Duration::from_secs(120),
        Box::new(Timed {
            grants: vec![
                Ok(Duration::from_secs(120)),
                Ok(MAP_LEASE),
                Err(MapFail::Timeout),
                Ok(MAP_LEASE),
            ],
            asked: Arc::clone(&asked),
            start,
        }),
    );
    let _ = tokio::time::timeout(Duration::from_secs(800), mapping.keep_renewed()).await;
    let s = Duration::from_secs;
    assert_eq!(
        *asked.lock().unwrap(),
        [s(60), s(120), s(420), s(450), s(750)]
    );
    assert_eq!(mapping.granted, MAP_LEASE);
}

/// A mapping released on drop with no runtime anywhere spawns nothing and
/// does not panic; one released explicitly no longer releases on drop.
#[test]
fn a_mapping_without_a_runtime_releases_nothing_on_drop() {
    let released = Arc::new(AtomicUsize::new(0));
    let tracker = ReleaseTracker::new();
    let mapping = Mapping::new(
        SocketAddrV4::new(Ipv4Addr::new(64, 0, 0, 9), 50_417),
        MapVia::Pcp,
        MAP_LEASE,
        Box::new(Scripted {
            grants: Vec::new(),
            released: Arc::clone(&released),
        }),
    )
    .release_on_drop(None, tracker.clone());
    drop(mapping);
    assert_eq!(released.load(Ordering::SeqCst), 0);
    assert_eq!(tracker.running(), 0);
}

/// A release that hangs is cut at [`MAP_RELEASE_CAP`]; `wait` returns as
/// soon as none runs, and reports one still running past its bound.
#[tokio::test(start_paused = true)]
async fn releases_are_capped_and_waited_for() {
    let tracker = ReleaseTracker::new();
    assert!(tracker.wait(Duration::ZERO).await);
    let rt = Handle::current();
    tracker.spawn(&rt, Box::pin(tokio::time::sleep(Duration::from_secs(3600))));
    assert_eq!(tracker.running(), 1);
    assert!(!tracker.wait(Duration::from_millis(500)).await);
    let start = tokio::time::Instant::now();
    assert!(tracker.wait(Duration::from_secs(5)).await);
    assert!(start.elapsed() <= MAP_RELEASE_CAP);
    assert_eq!(tracker.running(), 0);
}
