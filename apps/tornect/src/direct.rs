//! The direct path in the app (design `direct` §8.6): the knobs both roles
//! read ([`DirectKnobs`]), the bridge rule after each Tor bootstrap
//! (decision M1-86), the parts the host's and the viewer's halves are made
//! of ([`DirectWiring`]), the machine they run on and its router mappings'
//! lifecycle ([`real_net`], [`router_lifecycle`]), and the lines `doctor`
//! and the CLI print about the path. No line here ever names an address, a
//! port or a key (decision M1-83).

use std::fmt::Write as _;
use std::future::Future;
use std::sync::Arc;

use tornect_core::config::{self, BridgeMode, Network};
use tornect_core::session_log::{SessionEvent, SessionLog, SessionRecord, TransportKind};
use tornect_core::{Config, DeviceIdentity, Paths};
use tornect_net::{
    AddrClass, CandidateKind, IfaceAddr, IfaceKind, MapEvent, MapEvents, NetEnv, RealNet,
    RouteSources, SHUTDOWN_RELEASE_WAIT,
};
use tornect_session::{DirectSettings, INTERNET_DIRECT, Mine, PathEnd, ViewerDirect};
use tornect_signal::consent::{TransportKnob, TransportPolicy};
use tornect_signal::tor::Rung;

/// What the direct path is run with, as the settings and Tor change it:
/// the transport policy both roles read (the host signs it, the viewer
/// decides with it) and the `[network]` options of the path itself. Clones
/// share both, so a change reaches the next session without a restart.
#[derive(Clone, Debug)]
pub struct DirectKnobs {
    /// The effective transport policy: the privacy switches, and the bridge
    /// rule once Tor has said how it reaches the network.
    pub transport: TransportKnob,
    /// `network.direct_port` and `network.punch_timeout_ms`.
    pub direct: DirectSettings,
}

impl DirectKnobs {
    /// The knobs `cfg` asks for. Until the first bootstrap says which way
    /// Tor went in ([`DirectKnobs::bootstrapped`]), the bridge state is what
    /// the configuration alone tells ([`bridged`] with the plain rung): a
    /// configured bridge counts from the start, so nothing goes direct
    /// before Tor has said otherwise.
    #[must_use]
    pub fn new(cfg: &Config) -> Self {
        let transport = TransportKnob::new(&cfg.network);
        transport.set_bridged(bridged(Rung::Direct, &cfg.tor));
        Self {
            transport,
            direct: DirectSettings::from_network(&cfg.network),
        }
    }

    /// Tor has bootstrapped through `rung`: the bridge rule from now on
    /// (decision M1-86), after every bootstrap.
    pub fn bootstrapped(&self, rung: Rung, tor: &config::Tor) {
        self.transport.set_bridged(bridged(rung, tor));
    }

    /// The `[network]` settings saved now (design `direct` §3.3: after each
    /// save from the window): the privacy switches, the bridge override and
    /// the path's options, for the sessions that start from now on. The
    /// bridge state stays what the last bootstrap said.
    pub fn set_from(&self, net: &Network) {
        self.transport.set_from(net);
        self.direct.set_from(net);
    }
}

/// Whether Tor reaches the network through a bridge (decision M1-86): the
/// rung it bootstrapped on is not plain Tor, or the configuration names
/// bridges (its own bridge lines, or an obfs4 or Snowflake mode).
#[must_use]
pub fn bridged(rung: Rung, tor: &config::Tor) -> bool {
    rung != Rung::Direct
        || !tor.bridge_lines.is_empty()
        || matches!(tor.bridges, BridgeMode::Obfs4 | BridgeMode::Snowflake)
}

/// What both halves of the direct path are made of: this device's key (the
/// QUIC identity, and how a session with itself is recognised), the knobs,
/// and the machine.
#[derive(Clone)]
pub struct DirectWiring {
    /// This computer's device identity.
    pub device: Arc<DeviceIdentity>,
    /// The knobs.
    pub knobs: DirectKnobs,
    /// The network the links run on ([`RealNet`] outside tests).
    pub net: Arc<dyn NetEnv>,
}

/// This machine's network for direct links, built once per process (design
/// `direct` §8.6, "RealNet lifecycle") and shared by every session of it.
/// On Windows it reads each interface's IPv4 gateway with
/// `tornect-platform`'s `GetBestRoute2` lookup, which sends nothing:
/// netdev's own Windows gateway read may send ARP and is never compiled
/// (design §7.1). Linux and macOS read it through netdev. Its router
/// mappings (design §7.4) keep their ledger in `paths`'
/// `router_ports_dir` and are told to `sessions.log` ([`RouterPortLog`]).
#[must_use]
pub fn real_net(paths: &Paths) -> Arc<RealNet> {
    #[cfg(windows)]
    let net = RealNet::new().with_gateway_lookup(tornect_platform::route::default_gateway_v4);
    #[cfg(not(windows))]
    let net = RealNet::new();
    Arc::new(net.with_router(
        paths.router_ports_dir(),
        Arc::new(RouterPortLog::new(paths)),
    ))
}

/// Where this process's router mappings are told (design `direct` §8.1):
/// one `router_port` line in `sessions.log` for each mapping opened,
/// released, failed to release, or left by an earlier run and removed. The
/// line holds the change and the protocol, fixed words only, never an
/// address or a port.
pub struct RouterPortLog {
    log: SessionLog,
}

impl RouterPortLog {
    /// The lines go to `paths`' `sessions.log`.
    #[must_use]
    pub fn new(paths: &Paths) -> Self {
        Self {
            log: SessionLog::new(paths.sessions_log()),
        }
    }
}

impl MapEvents for RouterPortLog {
    fn on_event(&self, ev: MapEvent) {
        // One short line and its fsync, a few times a session at most:
        // written in place, as the signalling FSM's own sink writes its
        // lines from its tasks.
        let record = SessionRecord::now(SessionEvent::RouterPort).detail(ev.router_port().detail());
        if let Err(e) = self.log.append(&record) {
            tracing::warn!(error = %e, "could not append a router_port line to sessions.log");
        }
    }
}

impl std::fmt::Debug for RouterPortLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouterPortLog").finish_non_exhaustive()
    }
}

/// The start of the router mappings' lifecycle (design `direct` §7.4,
/// §8.6), on the current tokio runtime: the removal of the mappings an
/// earlier run left begins in the background, bounded by
/// [`tornect_net::SWEEP_CAP`], whatever the direct-path policy (it only
/// removes exposure), and never delays the start. Its handle is not kept:
/// a process that exits first leaves the rest to its next start.
pub fn sweep_router_leftovers(net: &RealNet) {
    drop(net.sweep_leftovers());
}

/// The end of it: waits, at most [`SHUTDOWN_RELEASE_WAIT`], for the
/// releases of the mappings this process's links held; whether none still
/// runs. A release unfinished by then lapses with the router's lease, and
/// its ledger entry is the next start's to sweep.
pub async fn wait_router_releases(net: &RealNet) -> bool {
    // A link closed just before this drops its mapping when its aborted
    // gathering task is next polled, and only then is the release counted:
    // one yield lets the runtime get there first.
    tokio::task::yield_now().await;
    net.releases().wait(SHUTDOWN_RELEASE_WAIT).await
}

/// `run` inside the router mappings' lifecycle: the sweep starts before it
/// ([`sweep_router_leftovers`]) and the releases get their wait after it
/// ([`wait_router_releases`]). The `host` and `connect` commands run in it.
pub async fn router_lifecycle<T>(net: &RealNet, run: impl Future<Output = T>) -> T {
    sweep_router_leftovers(net);
    let out = run.await;
    if !wait_router_releases(net).await {
        tracing::debug!("a router mapping's release was still running at exit");
    }
    out
}

impl DirectWiring {
    /// The parts for `device` on this process's machine ([`real_net`]),
    /// with `knobs`.
    #[must_use]
    pub fn real(device: Arc<DeviceIdentity>, knobs: DirectKnobs, net: Arc<RealNet>) -> Self {
        Self { device, knobs, net }
    }

    /// The device key's public half.
    #[must_use]
    pub fn device_pk(&self) -> [u8; 32] {
        self.device.verifying_key().to_bytes()
    }

    /// What one viewer session's path phase runs with (design `direct`
    /// §8.6 `DirectCtx`): the viewer's half for this device, the knobs'
    /// direct settings read now, and this computer's policy now
    /// ([`Mine::from_knob`], the bridge rule included), or `tor_only` for
    /// `connect --tor-only`. Built after the Tor bootstrap, once per
    /// session.
    #[must_use]
    pub fn ctx(&self, tor_only: bool) -> DirectCtx {
        DirectCtx {
            viewer: ViewerDirect::new(
                Arc::clone(&self.device),
                self.knobs.direct.clone(),
                Arc::clone(&self.net),
            ),
            mine: if tor_only {
                Mine::of(TransportPolicy::TorOnly)
            } else {
                Mine::from_knob(&self.knobs.transport)
            },
            device_pk: self.device_pk(),
            on_route: None,
        }
    }

    /// Parts for a test: the device of `seed`, the default knobs, and a
    /// network with no interface at all, so that nothing a test does goes
    /// direct unless it says so.
    #[cfg(test)]
    #[must_use]
    pub fn for_test(seed: u8) -> Self {
        Self {
            device: Arc::new(DeviceIdentity::from_seed(&[seed; 32])),
            knobs: DirectKnobs::new(&Config::default()),
            net: no_network(),
        }
    }
}

/// A test machine with no interface at all: a direct path started on it
/// finds no address, and nothing goes on any wire.
#[cfg(test)]
#[must_use]
pub fn no_network() -> Arc<dyn NetEnv> {
    Arc::new(tornect_net::mem::MemNet::new(1).machine(tornect_net::mem::MachineSpec::default()))
}

/// Where a viewer session's route goes as soon as it is known (design
/// `direct` §3.1, §8.6 `on_route`; the window's model): the path the path
/// phase chose, then, when a direct connection the host's TLS refused falls
/// back (decision M1-79's one exception), the Tor route that replaced it.
pub type OnRoute = Arc<dyn Fn(PathEnd) + Send + Sync>;

/// One viewer session's direct path (design `direct` §8.6).
pub struct DirectCtx {
    /// The viewer's half of the path.
    pub viewer: ViewerDirect,
    /// This computer's policy for the session.
    pub mine: Mine,
    /// This device's public key: a host with the same key is this computer
    /// (the decision's `same_key`).
    pub device_pk: [u8; 32],
    /// Who is told the session's route ([`OnRoute`]); `None` on the
    /// command line, which prints its `ROUTE` line once the media is bound.
    pub on_route: Option<OnRoute>,
}

impl DirectCtx {
    /// This context, telling `on_route` the session's route.
    #[must_use]
    pub fn reporting(mut self, on_route: OnRoute) -> Self {
        self.on_route = Some(on_route);
        self
    }

    /// Tell the session's route, if anyone listens.
    pub(crate) fn tell(&self, end: PathEnd) {
        if let Some(on_route) = &self.on_route {
            on_route(end);
        }
    }
}

impl std::fmt::Debug for DirectCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectCtx")
            .field("mine", &self.mine)
            .field("viewer", &self.viewer.stats())
            .field("reports_route", &self.on_route.is_some())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for DirectWiring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectWiring")
            .field("knobs", &self.knobs)
            .finish_non_exhaustive()
    }
}

/// The host's line when a session's capture starts (design `direct` §3.5):
/// `SESSION ROUTE <session> lan|direct|tor`.
#[must_use]
pub fn session_route_line(session_id: &str, route: TransportKind) -> String {
    let route = match route {
        TransportKind::Lan => "lan",
        TransportKind::Direct => "direct",
        TransportKind::TorRelay => "tor",
    };
    format!("SESSION ROUTE {session_id} {route}")
}

/// The viewer's `ROUTE` line (design `direct` §3.5): `ROUTE direct lan`,
/// `ROUTE tor <reason>`, `ROUTE none`, `ROUTE none no-lan-path`, ...
#[must_use]
pub fn route_line(end: &PathEnd) -> String {
    format!("ROUTE {}", end.route_words())
}

/// The viewer's `PATH` line (design `direct` §3.5): the kind of the host
/// candidate that won (`-` on Tor) and the time from the accept to the open
/// direct stream or to `TOR_FALLBACK`, in whole milliseconds.
#[must_use]
pub fn path_line(winner: Option<CandidateKind>, elapsed: std::time::Duration) -> String {
    format!(
        "PATH {} {} ms",
        winner.map_or("-", CandidateKind::name),
        elapsed.as_millis()
    )
}

/// `doctor`'s `direct connections:` line (design `direct` §3.5), for the
/// `[network]` switches and whether Tor goes through a bridge.
#[must_use]
pub fn direct_line(network: &Network, bridged: bool) -> String {
    let knob = TransportKnob::new(network);
    knob.set_bridged(bridged);
    let state = match knob.get() {
        TransportPolicy::TorOnly if knob.off_by_bridge() => {
            "off while Tor uses a bridge (network.direct_with_bridges to override)"
        }
        TransportPolicy::TorOnly => "off (paranoid)",
        TransportPolicy::LanOnly => "local network only, no Tor fallback (lan_only)",
        TransportPolicy::Any if INTERNET_DIRECT => "on (local network and internet)",
        TransportPolicy::Any => "on (local network only in this build)",
    };
    format!("direct connections: {state}")
}

/// Whether `doctor` expects Tor to go through a bridge, without starting
/// it: [`bridged`] with the rung that worked last time (`last_good`), plain
/// Tor when none has.
#[must_use]
pub fn bridged_expected(tor: &config::Tor, last_good: Option<Rung>) -> bool {
    bridged(last_good.unwrap_or(Rung::Direct), tor)
}

/// `doctor`'s `network:` line (design `direct` §3.5): the kinds of address
/// this computer has that a direct connection could use (up, on a physical
/// interface, not deprecated, tentative or hardware-derived), then the VPN
/// rule; `no usable address` when it has none. Kinds only, never an
/// address.
#[must_use]
pub fn network_line(addrs: &[IfaceAddr], sources: &RouteSources) -> String {
    let usable = |a: &&IfaceAddr| a.usable() && a.iface_kind == IfaceKind::Physical;
    let has = |class: AddrClass, v4: bool| {
        addrs
            .iter()
            .filter(usable)
            .any(|a| a.class == class && a.ip.is_ipv4() == v4)
    };
    let mut clauses: Vec<&str> = Vec::new();
    if has(AddrClass::Private, true) {
        clauses.push("private IPv4 present");
    }
    if has(AddrClass::UniqueLocal, false) {
        clauses.push("IPv6 unique-local present");
    }
    let global_v6: Vec<&IfaceAddr> = addrs
        .iter()
        .filter(usable)
        .filter(|a| a.class == AddrClass::Global && a.ip.is_ipv6())
        .collect();
    if global_v6.iter().any(|a| a.temporary) {
        clauses.push("global IPv6 present (temporary)");
    } else if !global_v6.is_empty() {
        clauses.push("global IPv6 present (stable, not hardware-derived)");
    }
    if has(AddrClass::Global, true) {
        clauses.push("public IPv4 on this computer");
    }
    if clauses.is_empty() {
        clauses.push("no usable address");
    }
    if tornect_net::local::vpn_mode(addrs, sources) {
        clauses.push("VPN mode (direct connections use the tunnel only)");
    }
    let mut line = String::from("network:");
    for (i, clause) in clauses.iter().enumerate() {
        let _ = write!(line, "{}{clause}", if i == 0 { " " } else { ", " });
    }
    line
}

/// `doctor`'s direct-path lines (design `direct` §3.5, Phase A): the state
/// of direct connections for `cfg` (the bridge expected from `last_good`),
/// then the kinds of address this computer has. The interfaces are read as
/// a session reads them, at most one second; nothing is sent.
#[must_use]
pub fn doctor_lines(cfg: &Config, last_good: Option<Rung>) -> Vec<String> {
    let mut lines = vec![direct_line(
        &cfg.network,
        bridged_expected(&cfg.tor, last_good),
    )];
    let read = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())
        .and_then(|rt| {
            rt.block_on(tornect_net::local::read_interfaces())
                .map_err(|e| e.to_string())
        });
    lines.push(match read {
        Ok(addrs) => network_line(&addrs, &tornect_net::local::route_sources()),
        Err(why) => format!("network: the interface list could not be read ({why})"),
    });
    lines
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    use tornect_net::Route;
    use tornect_session::{FallbackWhy, TorWhy};

    use super::*;

    fn tor(bridges: BridgeMode, lines: usize) -> config::Tor {
        config::Tor {
            bridges,
            bridge_lines: vec!["obfs4 192.0.2.1:443 0 cert=x iat-mode=0".to_owned(); lines],
            ..config::Tor::default()
        }
    }

    /// Decision M1-86: a bridge is a rung other than plain Tor, a bridge
    /// line of one's own, or a mode that names bridges, whatever the rung.
    #[test]
    fn the_bridge_rule_reads_the_rung_and_the_configuration() {
        for rung in Rung::ALL {
            for mode in [
                BridgeMode::Auto,
                BridgeMode::Off,
                BridgeMode::Obfs4,
                BridgeMode::Snowflake,
            ] {
                for lines in [0, 1] {
                    let want = rung != Rung::Direct
                        || lines > 0
                        || matches!(mode, BridgeMode::Obfs4 | BridgeMode::Snowflake);
                    assert_eq!(
                        bridged(rung, &tor(mode, lines)),
                        want,
                        "{rung} {mode:?} {lines}"
                    );
                }
            }
        }
    }

    /// Decision M1-86 through the knobs: a configuration that names a
    /// bridge is bridged from the start, before any bootstrap, unless
    /// `direct_with_bridges` overrides it; each bootstrap sets the state
    /// again from its rung; clones share it.
    #[test]
    fn the_knobs_start_from_the_configuration_and_follow_each_bootstrap() {
        let mut cfg = Config::default();
        let knobs = DirectKnobs::new(&cfg);
        let shared = knobs.clone();
        assert_eq!(knobs.transport.get(), TransportPolicy::Any);
        shared.bootstrapped(Rung::Obfs4, &cfg.tor);
        assert_eq!(knobs.transport.get(), TransportPolicy::TorOnly, "shared");
        assert!(knobs.transport.off_by_bridge());
        knobs.bootstrapped(Rung::Direct, &cfg.tor);
        assert_eq!(knobs.transport.get(), TransportPolicy::Any);

        cfg.tor.bridges = BridgeMode::Snowflake;
        cfg.network.punch_timeout_ms = 2500;
        let configured = DirectKnobs::new(&cfg);
        assert_eq!(
            configured.transport.get(),
            TransportPolicy::TorOnly,
            "bridged before the bootstrap"
        );
        assert_eq!(
            configured.direct.get().punch_timeout,
            Duration::from_millis(2500)
        );
        cfg.network.direct_with_bridges = true;
        assert_eq!(
            DirectKnobs::new(&cfg).transport.get(),
            TransportPolicy::Any,
            "the override"
        );
    }

    /// Design `direct` §3.3: a save from the window reaches every clone of
    /// the knobs (the host role holds one): the privacy switches, the
    /// bridge override and the path's options; the bridge state stays what
    /// the last bootstrap said.
    #[test]
    fn a_saved_network_reaches_every_clone_of_the_knobs() {
        let cfg = Config::default();
        let knobs = DirectKnobs::new(&cfg);
        let held = knobs.clone();
        let mut net = cfg.network.clone();
        net.paranoid = true;
        net.punch_timeout_ms = 3000;
        knobs.set_from(&net);
        assert_eq!(held.transport.get(), TransportPolicy::TorOnly);
        assert_eq!(held.direct.get().punch_timeout, Duration::from_millis(3000));
        // A bridge since the last bootstrap: on again, still off by the
        // bridge rule until the override is saved too.
        knobs.bootstrapped(Rung::Snowflake, &cfg.tor);
        net.paranoid = false;
        knobs.set_from(&net);
        assert!(held.transport.off_by_bridge());
        assert_eq!(held.transport.get(), TransportPolicy::TorOnly);
        net.direct_with_bridges = true;
        knobs.set_from(&net);
        assert_eq!(held.transport.get(), TransportPolicy::Any);
        net.lan_only = true;
        knobs.set_from(&net);
        assert_eq!(held.transport.get(), TransportPolicy::LanOnly);
    }

    /// Design `direct` §3.5: the host's `SESSION ROUTE` line names the
    /// route a session's capture started on, in one word.
    #[test]
    fn the_session_route_line_names_the_route() {
        assert_eq!(
            session_route_line("ab12", TransportKind::Lan),
            "SESSION ROUTE ab12 lan"
        );
        assert_eq!(
            session_route_line("ab12", TransportKind::Direct),
            "SESSION ROUTE ab12 direct"
        );
        assert_eq!(
            session_route_line("ab12", TransportKind::TorRelay),
            "SESSION ROUTE ab12 tor"
        );
    }

    /// Design `direct` §3.5: the `ROUTE` and `PATH` lines as the design
    /// words them.
    #[test]
    fn the_route_and_path_lines_say_the_route_the_winner_and_the_time() {
        let lan = Route {
            same_site: true,
            ipv6: false,
        };
        let lan6 = Route {
            same_site: true,
            ipv6: true,
        };
        for (end, line) in [
            (PathEnd::Direct(lan), "ROUTE direct lan"),
            (PathEnd::Direct(lan6), "ROUTE direct lan ipv6"),
            (PathEnd::Tor(TorWhy::OldHost), "ROUTE tor old-host"),
            (
                PathEnd::Tor(TorWhy::Fallback(FallbackWhy::NoPath { heard: true })),
                "ROUTE tor no-path-firewall",
            ),
            (PathEnd::NoMedia, "ROUTE none"),
            (PathEnd::LanRefused, "ROUTE none no-lan-path"),
        ] {
            assert_eq!(route_line(&end), line);
        }
        assert_eq!(
            path_line(Some(CandidateKind::Host), Duration::from_micros(412_900)),
            "PATH host 412 ms"
        );
        assert_eq!(
            path_line(None, Duration::from_millis(4000)),
            "PATH - 4000 ms"
        );
    }

    /// Design `direct` §3.5: `doctor`'s `direct connections:` line for each
    /// policy, the bridge, its override, and this build's scope.
    #[test]
    fn doctor_says_whether_direct_connections_are_on() {
        // Phase A says the scope of this build (`INTERNET_DIRECT` off).
        let on = if INTERNET_DIRECT {
            "direct connections: on (local network and internet)"
        } else {
            "direct connections: on (local network only in this build)"
        };
        let mut net = Network::default();
        assert_eq!(direct_line(&net, false), on);
        assert_eq!(
            direct_line(&net, true),
            "direct connections: off while Tor uses a bridge (network.direct_with_bridges to \
             override)"
        );
        net.direct_with_bridges = true;
        assert_eq!(direct_line(&net, true), on);
        net.lan_only = true;
        assert_eq!(
            direct_line(&net, true),
            "direct connections: local network only, no Tor fallback (lan_only)"
        );
        net.lan_only = false;
        net.paranoid = true;
        for bridged in [false, true] {
            assert_eq!(
                direct_line(&net, bridged),
                "direct connections: off (paranoid)"
            );
        }
        assert!(bridged_expected(
            &tor(BridgeMode::Auto, 0),
            Some(Rung::Snowflake)
        ));
        assert!(!bridged_expected(&tor(BridgeMode::Auto, 0), None));
        assert!(bridged_expected(&tor(BridgeMode::Obfs4, 0), None));
    }

    fn addr(ip: IpAddr, class: AddrClass, kind: IfaceKind, index: u32) -> IfaceAddr {
        IfaceAddr {
            ip,
            prefix_len: if ip.is_ipv4() { 24 } else { 64 },
            class,
            temporary: false,
            deprecated: false,
            tentative: false,
            duplicated: false,
            eui64: false,
            iface_index: index,
            iface_kind: kind,
            up: true,
            gateway_v4: None,
        }
    }

    /// Design `direct` §3.5: `doctor`'s `network:` line names the kinds of
    /// address a direct connection could use, never an address; an address
    /// that is down, deprecated, hardware-derived or not on a physical
    /// interface does not count; the VPN rule is said last.
    #[test]
    fn doctor_names_the_kinds_of_address_and_never_one() {
        let private = Ipv4Addr::new(192, 168, 1, 20);
        let public = Ipv4Addr::new(203, 0, 113, 7);
        let ula: Ipv6Addr = "fd12:3456:789a::20".parse().unwrap();
        let global: Ipv6Addr = "2001:db8:1::20".parse().unwrap();
        let none = RouteSources::default();
        assert_eq!(network_line(&[], &none), "network: no usable address");

        let mut all = vec![
            addr(private.into(), AddrClass::Private, IfaceKind::Physical, 2),
            addr(ula.into(), AddrClass::UniqueLocal, IfaceKind::Physical, 2),
            addr(global.into(), AddrClass::Global, IfaceKind::Physical, 2),
            addr(public.into(), AddrClass::Global, IfaceKind::Physical, 2),
        ];
        let sources = RouteSources {
            v4: Some(private),
            v6: Some(global),
        };
        let line = network_line(&all, &sources);
        assert_eq!(
            line,
            "network: private IPv4 present, IPv6 unique-local present, global IPv6 present \
             (stable, not hardware-derived), public IPv4 on this computer"
        );
        for ip in ["192.168", "203.0", "fd12", "2001"] {
            assert!(!line.contains(ip), "{line}");
        }
        all[2].temporary = true;
        assert!(network_line(&all, &sources).contains("global IPv6 present (temporary)"));

        let mut unusable = all.clone();
        unusable[0].up = false;
        unusable[1].deprecated = true;
        unusable[2].eui64 = true;
        unusable[3].iface_kind = IfaceKind::Virtual;
        assert_eq!(network_line(&unusable, &none), "network: no usable address");

        let tunnel = vec![
            addr(private.into(), AddrClass::Private, IfaceKind::Physical, 2),
            addr(
                Ipv4Addr::new(10, 8, 0, 2).into(),
                AddrClass::Private,
                IfaceKind::Tunnel,
                9,
            ),
        ];
        let through_tunnel = RouteSources {
            v4: Some(Ipv4Addr::new(10, 8, 0, 2)),
            v6: None,
        };
        assert_eq!(
            network_line(&tunnel, &through_tunnel),
            "network: private IPv4 present, VPN mode (direct connections use the tunnel only)"
        );
    }

    /// `doctor` reads this machine's interfaces as a session does and
    /// prints kinds only: two lines, the second `network:`.
    #[test]
    fn doctor_reads_this_machine_without_naming_an_address() {
        let lines = doctor_lines(&Config::default(), None);
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[0].starts_with("direct connections: "), "{lines:?}");
        assert!(lines[1].starts_with("network: "), "{lines:?}");
        assert!(
            !lines[1]
                .chars()
                .any(|c| c.is_ascii_digit() && !"46".contains(c)),
            "only IPv4 and IPv6 may carry a digit: {lines:?}"
        );
    }

    /// Design `direct` §8.1: each router mapping event is one
    /// `router_port` line holding the change and the protocol, fixed words
    /// only, with no session, peer, address or port.
    #[test]
    fn router_mapping_events_are_router_port_lines_of_fixed_words() {
        use tornect_net::MapVia;

        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        let sink = RouterPortLog::new(&paths);
        sink.on_event(MapEvent::Opened(MapVia::Pcp));
        sink.on_event(MapEvent::Closed(MapVia::Pcp));
        sink.on_event(MapEvent::CloseFailed(MapVia::NatPmp));
        sink.on_event(MapEvent::LeftoverRemoved(MapVia::Upnp));
        let records = SessionLog::new(paths.sessions_log()).read_all().unwrap();
        let details: Vec<_> = records
            .iter()
            .map(|r| {
                assert_eq!(r.event, SessionEvent::RouterPort);
                assert!(r.session_id.is_none() && r.peer_device.is_none() && r.peer_name.is_none());
                assert!(r.transport.is_none());
                r.detail.clone().unwrap()
            })
            .collect();
        assert_eq!(
            details,
            [
                "opened pcp",
                "closed pcp",
                "close-failed nat-pmp",
                "leftover-removed upnp"
            ]
        );
        assert!(!format!("{sink:?}").contains(&*tmp.path().to_string_lossy()));
    }

    /// Design `direct` §8.6: the process's machine has the router ledger
    /// (only a machine with one starts a sweep), and the lifecycle a command
    /// runs in returns what the command returned only once the releases
    /// running at its end are done.
    #[tokio::test]
    async fn the_router_lifecycle_sweeps_at_start_and_waits_for_releases_at_exit() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        let net = real_net(&paths);
        let sweep = net.sweep_leftovers().expect("a router ledger");
        assert_eq!(sweep.await.unwrap(), tornect_net::SweepReport::default());
        assert!(
            RealNet::new().sweep_leftovers().is_none(),
            "no ledger, no sweep"
        );

        let releases = net.releases();
        let started = std::time::Instant::now();
        let out = router_lifecycle(&net, async {
            releases.spawn(
                &tokio::runtime::Handle::current(),
                Box::pin(tokio::time::sleep(Duration::from_millis(150))),
            );
            7
        })
        .await;
        assert_eq!(out, 7);
        assert_eq!(releases.running(), 0, "the release ended before the exit");
        assert!(started.elapsed() >= Duration::from_millis(150));
        // Nothing to release: the wait returns at once.
        let started = std::time::Instant::now();
        assert!(wait_router_releases(&net).await);
        assert!(started.elapsed() < SHUTDOWN_RELEASE_WAIT);
    }
}
