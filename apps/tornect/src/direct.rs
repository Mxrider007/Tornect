//! The direct path in the app (design `direct` §8.6): the knobs both roles
//! read ([`DirectKnobs`]), the bridge rule after each Tor bootstrap
//! (decision M1-86), the parts the host's and the viewer's halves are made
//! of ([`DirectWiring`]), the machine they run on and its router mappings'
//! lifecycle ([`RouterPorts`], [`router_lifecycle`]), and the lines `doctor`
//! and the CLI print about the path. No line here ever names an address, a
//! port or a key (decision M1-83).

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::future::Future;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tornect_core::config::{self, BridgeMode, Network};
use tornect_core::session_log::{SessionEvent, SessionLog, SessionRecord, TransportKind};
use tornect_core::{Config, DeviceIdentity, Paths};
use tornect_net::{
    AddrClass, CandidateKind, IfaceAddr, IfaceKind, MapEvent, MapEvents, MappingLedger, NetEnv,
    RealNet, RouteSources, SHUTDOWN_RELEASE_WAIT, TornectRole,
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
    /// This process's router mappings, when `net` is their machine: the
    /// host's wiring sends their lines through its one handle on
    /// `sessions.log` ([`RouterPorts::hosting`]). `None` in tests.
    pub router: Option<RouterPorts>,
}

/// This process's router mappings (design `direct` §7.4, §8.6): the machine
/// its direct links run on, whose router mapper makes them, and the
/// `sessions.log` lines that tell them ([`RouterPortLog`]). Built once per
/// process ([`RouterPorts::new`]) and shared by every session of it; clones
/// share everything.
///
/// The lines go through the host's one handle on `sessions.log` once the
/// host's wiring has it ([`RouterPorts::hosting`]), and in a process that
/// runs no host through the handle every line of such a process goes
/// through ([`RouterPorts::not_hosting`]), keyed as the host's store keys its
/// own: a second handle beside the host's would write untagged lines after
/// the chain started, or fork the chain (§B.8.13). The sweep of an earlier
/// run's leftovers, which writes lines, starts only then.
#[derive(Clone)]
pub struct RouterPorts {
    net: Arc<RealNet>,
    log: Arc<RouterPortLog>,
    /// Whether the sweep was started.
    swept: Arc<AtomicBool>,
    /// The STUN names the running refresh started with
    /// ([`RouterPorts::follow_stun`]); `None` before it starts.
    stun: Arc<Mutex<Option<Vec<String>>>>,
}

impl RouterPorts {
    /// This machine's network for direct links with its router ledger in
    /// `paths`' `router_ports_dir` and its lines for `paths`'
    /// `sessions.log`. On Windows it reads each interface's IPv4 gateway with
    /// `tornect-platform`'s `GetBestRoute2` lookup, which sends nothing:
    /// netdev's own Windows gateway read may send ARP and is never compiled
    /// (design §7.1). Linux and macOS read it through netdev.
    #[must_use]
    pub fn new(paths: &Paths) -> Self {
        #[cfg(windows)]
        let net = RealNet::new().with_gateway_lookup(tornect_platform::route::default_gateway_v4);
        #[cfg(not(windows))]
        let net = RealNet::new();
        let log = Arc::new(RouterPortLog::new(paths));
        Self {
            net: Arc::new(net.with_router(
                paths.router_ports_dir(),
                Arc::clone(&log) as Arc<dyn MapEvents>,
            )),
            log,
            swept: Arc::new(AtomicBool::new(false)),
            stun: Arc::new(Mutex::new(None)),
        }
    }

    /// The machine.
    #[must_use]
    pub fn net(&self) -> &Arc<RealNet> {
        &self.net
    }

    /// Where the mappings are told.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn log(&self) -> &Arc<RouterPortLog> {
        &self.log
    }

    /// This process is the host, and `log` its one handle on `sessions.log`
    /// (keyed by its store): every router line goes through it from now on,
    /// and the sweep starts. The host's wiring calls it once it has the
    /// handle, before any session.
    pub fn hosting(&self, log: &SessionLog) {
        self.log.attach(log.clone());
        self.sweep();
    }

    /// This process runs no host (`connect`, a window without its host
    /// role): the sweep starts, its lines written as the process's other
    /// lines are ([`RouterPortLog`]). Nothing when the host's wiring already
    /// started it.
    pub fn not_hosting(&self) {
        self.sweep();
    }

    /// The background refresh of the STUN servers' names follows `knobs`
    /// (design `direct` §5.3, [`RealNet::prefetch`]): it starts at the
    /// first call, and starts again, with a round at once, whenever the
    /// names [`stun_names`] gives for `roles` changed since the refresh
    /// started. The app calls it at start, after each Tor bootstrap (the
    /// bridge state) and after each settings save: a refresh that kept
    /// running would leave a cleared cache cold, and a newly listed name
    /// unanswered, until its next round, 10 minutes on. Each round reads
    /// the knobs again; while no session may ask a STUN server the list is
    /// empty, so nothing is looked up and the cache is emptied. Whether a
    /// refresh was started (never outside a tokio runtime).
    pub fn follow_stun(&self, knobs: &DirectKnobs, roles: &'static [TornectRole]) -> bool {
        self.follow_stun_in(knobs, roles, INTERNET_DIRECT)
    }

    /// [`follow_stun`](Self::follow_stun) for a build whose direct
    /// connections reach the internet (`internet`) or not.
    fn follow_stun_in(
        &self,
        knobs: &DirectKnobs,
        roles: &'static [TornectRole],
        internet: bool,
    ) -> bool {
        let names = stun_names(knobs, roles, internet);
        let mut started = self.stun.lock().unwrap_or_else(PoisonError::into_inner);
        if started.as_ref() == Some(&names) {
            return false;
        }
        let knobs = knobs.clone();
        if !self
            .net
            .prefetch(move || stun_names(&knobs, roles, internet))
        {
            return false;
        }
        *started = Some(names);
        true
    }

    /// The removal of the mappings an earlier run left begins in the
    /// background on the current tokio runtime, bounded by
    /// [`tornect_net::SWEEP_CAP`], whatever the direct-path policy (it only
    /// removes exposure), and never delays the start. Its handle is not
    /// kept: a process that exits first leaves the rest to its next start.
    /// Once per process; whether this call started it.
    fn sweep(&self) -> bool {
        if self.swept.swap(true, Ordering::SeqCst) {
            return false;
        }
        drop(self.net.sweep_leftovers());
        true
    }

    /// The end of it: waits, at most [`SHUTDOWN_RELEASE_WAIT`], for the
    /// releases of the mappings this process's links held, then, at most
    /// [`PORT_LINES_WAIT`], for the lines still to write (a release's
    /// `closed` among them); whether both finished. A link that ended before
    /// this call counts its mapping's release from the moment it ended, so
    /// the wait cannot miss it. A release unfinished by then lapses with the
    /// router's lease, and its ledger entry is the next start's to sweep; so
    /// does the mapping of a link still open at exit.
    pub async fn wind_down(&self) -> bool {
        let released = self.net.releases().wait(SHUTDOWN_RELEASE_WAIT).await;
        let log = Arc::clone(&self.log);
        let written = tokio::task::spawn_blocking(move || log.flush(PORT_LINES_WAIT))
            .await
            .unwrap_or(false);
        released && written
    }
}

impl std::fmt::Debug for RouterPorts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouterPorts")
            .field("log", &self.log)
            .finish_non_exhaustive()
    }
}

/// The roles of a process that only connects (`connect`).
pub const VIEWER: &[TornectRole] = &[TornectRole::Viewer];

/// The roles of a process that only hosts (`host`).
pub const HOST: &[TornectRole] = &[TornectRole::Host];

/// The roles of a window that hosts and connects.
pub const BOTH: &[TornectRole] = &[TornectRole::Viewer, TornectRole::Host];

/// The STUN servers' names this process looks up ahead of its sessions
/// (design `direct` §5.3): the parts of `network.stun_servers` its `roles`
/// ask ([`tornect_net::partition`]), in order, each once, while a session
/// may ask a STUN server at all: a build whose direct connections reach the
/// internet (`internet`: [`INTERNET_DIRECT`] outside tests), the effective
/// policy `Any` (direct connections on, no bridge in use without its
/// override, not `lan_only`) and `enable_stun`. Otherwise none.
#[must_use]
pub fn stun_names(knobs: &DirectKnobs, roles: &[TornectRole], internet: bool) -> Vec<String> {
    if !internet || knobs.transport.get() != TransportPolicy::Any {
        return Vec::new();
    }
    let options = knobs.direct.get();
    if !options.enable_stun {
        return Vec::new();
    }
    let mut names: Vec<String> = Vec::new();
    for role in roles {
        for entry in options.gather(*role).stun_partition.iter() {
            if !names.contains(entry) {
                names.push(entry.clone());
            }
        }
    }
    names
}

/// `run`, then the end of the router mappings' lifecycle
/// ([`RouterPorts::wind_down`]). The `host` and `connect` commands run in it;
/// `connect` starts the sweep first ([`RouterPorts::not_hosting`]), the
/// host's wiring once it has its handle on `sessions.log`.
pub async fn router_lifecycle<T>(ports: &RouterPorts, run: impl Future<Output = T>) -> T {
    let out = run.await;
    if !ports.wind_down().await {
        tracing::debug!("a router mapping's release or line was still running at exit");
    }
    out
}

/// How many `router_port` lines wait at most for their writer; one more is
/// dropped and counted. A session makes a few, and they are written as fast
/// as `sessions.log` takes them: only a stalled disk fills this.
const PORT_LINES_QUEUE: usize = 64;

/// How long the exit waits, after the releases, for the router lines still
/// to write ([`RouterPorts::wind_down`]).
pub const PORT_LINES_WAIT: Duration = Duration::from_secs(1);

/// Where this process's router mappings are told (design `direct` §8.1):
/// one `router_port` line in `sessions.log` for each mapping opened,
/// released, failed to release, or left by an earlier run and removed. The
/// line holds the change and the protocol, fixed words only, never an
/// address or a port.
///
/// [`MapEvents::on_event`] runs on the mapper's tasks and in the drops of
/// its mappings, where nothing may block: it stamps the line and queues it
/// (at most [`PORT_LINES_QUEUE`], beyond that dropped and counted), and a
/// thread of its own appends and syncs the lines in order, through the
/// host's handle once [`attach`](Self::attach)ed and otherwise keyed as a
/// process that runs no host keys its lines (`ua_client::append_keyed`). The
/// thread ends when the queue is empty and the next line starts another.
pub struct RouterPortLog {
    lines: Arc<PortLines>,
}

/// The queue of a [`RouterPortLog`] and what its writer needs.
struct PortLines {
    /// The home whose `sessions.log` and keystore a line without a host
    /// handle goes through.
    paths: Paths,
    state: Mutex<PortState>,
    /// Told whenever the writer finds the queue empty and ends.
    idle: Condvar,
}

#[derive(Default)]
struct PortState {
    queue: VecDeque<SessionRecord>,
    /// The host's one handle on `sessions.log`, once attached.
    host: Option<SessionLog>,
    /// Whether a writer runs (it has a line in hand or more queued).
    writing: bool,
    /// Lines dropped on a full queue, all told.
    dropped: u64,
    /// How many of them a warning has named.
    reported: u64,
}

impl RouterPortLog {
    /// The lines go to `paths`' `sessions.log`.
    #[must_use]
    pub fn new(paths: &Paths) -> Self {
        Self {
            lines: Arc::new(PortLines {
                paths: paths.clone(),
                state: Mutex::new(PortState::default()),
                idle: Condvar::new(),
            }),
        }
    }

    /// From now on (the lines still queued included) every line goes
    /// through `log`, the host's one handle on `sessions.log`.
    pub fn attach(&self, log: SessionLog) {
        self.lines.lock().host = Some(log);
    }

    /// Waits, at most `max`, until every line handed over so far is written
    /// (or failed, which is logged); whether that happened. It blocks: an
    /// async caller runs it on a blocking thread.
    pub fn flush(&self, max: Duration) -> bool {
        let deadline = std::time::Instant::now() + max;
        let mut state = self.lines.lock();
        while state.writing {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return false;
            }
            state = self
                .lines
                .idle
                .wait_timeout(state, left)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        true
    }

    /// Lines dropped on a full queue so far.
    #[cfg(test)]
    fn dropped(&self) -> u64 {
        self.lines.lock().dropped
    }
}

impl PortLines {
    fn lock(&self) -> MutexGuard<'_, PortState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Queue `record`, and start the writer unless one runs.
    fn push(this: &Arc<Self>, record: SessionRecord) {
        let mut state = this.lock();
        if state.queue.len() >= PORT_LINES_QUEUE {
            state.dropped = state.dropped.saturating_add(1);
            return;
        }
        state.queue.push_back(record);
        if state.writing {
            return;
        }
        state.writing = true;
        drop(state);
        let lines = Arc::clone(this);
        let started = std::thread::Builder::new()
            .name("router-port-log".to_owned())
            .spawn(move || lines.write_queued());
        if let Err(e) = started {
            tracing::warn!(error = %e, "could not start the writer of router_port lines");
            let mut state = this.lock();
            let lost = u64::try_from(state.queue.len()).unwrap_or(u64::MAX);
            state.queue.clear();
            state.dropped = state.dropped.saturating_add(lost);
            state.writing = false;
            this.idle.notify_all();
        }
    }

    /// The writer: every queued line in order, until the queue is empty.
    fn write_queued(&self) {
        loop {
            let (record, host) = {
                let mut state = self.lock();
                let Some(record) = state.queue.pop_front() else {
                    state.writing = false;
                    let unreported = state.dropped - state.reported;
                    state.reported = state.dropped;
                    self.idle.notify_all();
                    drop(state);
                    if unreported > 0 {
                        tracing::warn!(
                            dropped = unreported,
                            "router_port lines were dropped: sessions.log was not written fast \
                             enough"
                        );
                    }
                    return;
                };
                (record, state.host.clone())
            };
            let written = match &host {
                Some(log) => log.append(&record).map_err(|e| e.to_string()),
                None => crate::ua_client::append_keyed(&self.paths, &record),
            };
            if let Err(e) = written {
                tracing::warn!(error = %e, "could not append a router_port line to sessions.log");
            }
        }
    }
}

impl MapEvents for RouterPortLog {
    fn on_event(&self, ev: MapEvent) {
        PortLines::push(
            &self.lines,
            SessionRecord::now(SessionEvent::RouterPort).detail(ev.router_port().detail()),
        );
    }
}

impl std::fmt::Debug for RouterPortLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.lines.lock();
        f.debug_struct("RouterPortLog")
            .field("attached", &state.host.is_some())
            .field("queued", &state.queue.len())
            .field("dropped", &state.dropped)
            .finish_non_exhaustive()
    }
}

impl DirectWiring {
    /// The parts for `device` on this process's machine ([`RouterPorts`]),
    /// with `knobs`.
    #[must_use]
    pub fn real(device: Arc<DeviceIdentity>, knobs: DirectKnobs, ports: &RouterPorts) -> Self {
        Self {
            device,
            knobs,
            net: Arc::clone(ports.net()) as Arc<dyn NetEnv>,
            router: Some(ports.clone()),
        }
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
            router: None,
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

/// The `host` command's line at its start (design `direct` §3.5) while
/// `policy`, the effective one once Tor has said how it reaches the
/// network, lets every accepted session learn this computer's IP address:
/// in a build whose direct connections reach the internet (`internet`), the
/// policy `Any`. None otherwise.
#[must_use]
pub fn notice_line(policy: TransportPolicy, internet: bool) -> Option<&'static str> {
    (internet && policy == TransportPolicy::Any).then_some(
        "NOTICE direct connections are on: a computer you accept learns this computer's IP \
         address (set network.paranoid = true to relay every session through Tor)",
    )
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
pub fn path_line(winner: Option<CandidateKind>, elapsed: Duration) -> String {
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

/// Whether a session of this computer may reach beyond the same site
/// with `network` (design `direct` §4): a build whose direct connections
/// reach the internet (`internet`), and the policy `Any` with the bridge
/// state `bridged`. Only then is a STUN server or the router asked.
#[must_use]
fn internet_scope(network: &Network, bridged: bool, internet: bool) -> bool {
    let knob = TransportKnob::new(network);
    knob.set_bridged(bridged);
    internet && knob.get() == TransportPolicy::Any
}

/// `doctor`'s `public STUN servers:` lines (design `direct` §3.5): on, with
/// the length of the list, while a session may ask one (`internet`: see
/// [`internet_scope`]) and `enable_stun` with a list; off otherwise. A list
/// that is not the default adds that the operator split holds only when
/// both computers use the same list (decision M1-81). No server is named.
#[must_use]
pub fn stun_lines(network: &Network, internet: bool) -> Vec<String> {
    if !internet || !network.enable_stun || network.stun_servers.is_empty() {
        return vec!["public STUN servers: off".to_owned()];
    }
    let mut lines = vec![format!(
        "public STUN servers: on, {} in the list, one asked per session",
        network.stun_servers.len()
    )];
    if network.stun_servers != Network::default().stun_servers {
        lines.push(
            "public STUN servers: not the default list; one operator may be asked by both \
             computers of a session unless both use the same list"
                .to_owned(),
        );
    }
    lines
}

/// `doctor`'s `router port mapping:` line (design `direct` §3.5): each
/// protocol on while a session may ask the router (`internet`: see
/// [`internet_scope`]) and its switch is on.
#[must_use]
pub fn router_line(network: &Network, internet: bool) -> String {
    let state = |on: bool| if internet && on { "on" } else { "off" };
    format!(
        "router port mapping: UPnP {}, NAT-PMP {}, PCP {}",
        state(network.upnp),
        state(network.nat_pmp),
        state(network.pcp)
    )
}

/// `doctor`'s `router ports left from an earlier run:` line (design
/// `direct` §3.5), only when there are any: `count` entries of the router
/// ledger whose process is gone, which the next start removes.
#[must_use]
pub fn leftover_line(count: usize) -> Option<String> {
    (count > 0).then(|| format!("router ports left from an earlier run: {count}"))
}

/// `doctor`'s direct-path lines (design `direct` §3.5): the state of
/// direct connections for `cfg` (the bridge expected from `last_good`),
/// whether a session asks a public STUN server and the router, the
/// mappings an earlier run left in the ledger in `router_dir`, then the
/// kinds of address this computer has. The interfaces are read as a
/// session reads them, at most one second; nothing is sent, and no
/// address, port or server is printed.
#[must_use]
pub fn doctor_lines(cfg: &Config, last_good: Option<Rung>, router_dir: &Path) -> Vec<String> {
    let bridged = bridged_expected(&cfg.tor, last_good);
    let internet = internet_scope(&cfg.network, bridged, INTERNET_DIRECT);
    let mut lines = vec![direct_line(&cfg.network, bridged)];
    lines.extend(stun_lines(&cfg.network, internet));
    lines.push(router_line(&cfg.network, internet));
    lines.extend(leftover_line(MappingLedger::leftovers(router_dir)));
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

    /// Design `direct` §3.5: `host` says at its start that an accepted
    /// computer learns this computer's IP address, in a build whose direct
    /// connections reach the internet and while the policy is `Any` only.
    #[test]
    fn the_host_notice_is_said_only_while_an_accept_reveals_the_ip_address() {
        assert_eq!(
            notice_line(TransportPolicy::Any, true),
            Some(
                "NOTICE direct connections are on: a computer you accept learns this \
                 computer's IP address (set network.paranoid = true to relay every session \
                 through Tor)"
            )
        );
        for (policy, internet) in [
            (TransportPolicy::Any, false),
            (TransportPolicy::TorOnly, true),
            (TransportPolicy::LanOnly, true),
            (TransportPolicy::TorOnly, false),
            (TransportPolicy::LanOnly, false),
        ] {
            assert_eq!(notice_line(policy, internet), None, "{policy:?} {internet}");
        }
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
        let internet = Route {
            same_site: false,
            ipv6: false,
        };
        let internet6 = Route {
            same_site: false,
            ipv6: true,
        };
        for (end, line) in [
            (PathEnd::Direct(lan), "ROUTE direct lan"),
            (PathEnd::Direct(lan6), "ROUTE direct lan ipv6"),
            (PathEnd::Direct(internet), "ROUTE direct internet"),
            (PathEnd::Direct(internet6), "ROUTE direct internet ipv6"),
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
    /// prints kinds only: the direct connections, STUN and router lines,
    /// then `network:`; with a router ledger an earlier run left, the count
    /// of its ports before `network:`.
    #[test]
    fn doctor_reads_this_machine_without_naming_an_address() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("router-ports");
        let lines = doctor_lines(&Config::default(), None, &dir);
        assert_eq!(lines.len(), 4, "{lines:?}");
        assert!(lines[0].starts_with("direct connections: "), "{lines:?}");
        assert!(lines[1].starts_with("public STUN servers: "), "{lines:?}");
        assert!(lines[2].starts_with("router port mapping: "), "{lines:?}");
        assert!(lines[3].starts_with("network: "), "{lines:?}");
        assert!(
            !lines[3]
                .chars()
                .any(|c| c.is_ascii_digit() && !"46".contains(c)),
            "only IPv4 and IPv6 may carry a digit: {lines:?}"
        );

        // A process that died holding two mappings: its list, its lock
        // file free.
        std::fs::create_dir_all(&dir).unwrap();
        let entry = tornect_net::LedgerEntry {
            via: tornect_net::MapVia::Pcp,
            gateway: Ipv4Addr::new(192, 168, 1, 1),
            client: Ipv4Addr::new(192, 168, 1, 20),
            internal_port: 40000,
            external_port: None,
            pcp_nonce: Some([1, 2, 3]),
            created: tornect_net::mapping::unix_now(),
        };
        let owner = "0123456789abcdef";
        std::fs::write(
            dir.join(format!("{owner}.cbor")),
            tornect_net::mapping::encode_list(&[entry.clone(), entry]),
        )
        .unwrap();
        std::fs::write(dir.join(format!("{owner}.lock")), b"").unwrap();
        let lines = doctor_lines(&Config::default(), None, &dir);
        assert_eq!(lines.len(), 5, "{lines:?}");
        assert_eq!(lines[3], "router ports left from an earlier run: 2");
        for line in &lines {
            for named in ["192.168", "40000"] {
                assert!(!line.contains(named), "{line}");
            }
        }
    }

    /// Design `direct` §3.5: `doctor`'s STUN and router lines say what a
    /// session does: on only in a build whose direct connections reach the
    /// internet, while the policy is `Any` (not paranoid, no bridge in use
    /// without the override, not `lan_only`), each by its own switch; the
    /// STUN line counts the list and names no server, and a list that is
    /// not the default says the operator split needs the same list on both
    /// computers. The leftover line shows only when there are some.
    #[test]
    fn doctor_says_whether_stun_servers_and_the_router_are_asked() {
        let net = Network::default();
        let n = net.stun_servers.len();
        let on = format!("public STUN servers: on, {n} in the list, one asked per session");
        let all_on = "router port mapping: UPnP on, NAT-PMP on, PCP on";
        let all_off = "router port mapping: UPnP off, NAT-PMP off, PCP off";
        assert_eq!(stun_lines(&net, true), vec![on.clone()]);
        assert_eq!(router_line(&net, true), all_on);
        // Not an internet build: neither is asked.
        assert_eq!(stun_lines(&net, false), vec!["public STUN servers: off"]);
        assert_eq!(router_line(&net, false), all_off);
        assert!(internet_scope(&net, false, true));
        assert!(!internet_scope(&net, false, false));
        // Every policy but Any keeps both off.
        let mut paranoid = net.clone();
        paranoid.paranoid = true;
        let mut lan = net.clone();
        lan.lan_only = true;
        for (case, network, bridged) in [
            ("paranoid", &paranoid, false),
            ("lan_only", &lan, false),
            ("a bridge", &net, true),
        ] {
            assert!(!internet_scope(network, bridged, true), "{case}");
        }
        let mut overridden = net.clone();
        overridden.direct_with_bridges = true;
        assert!(internet_scope(&overridden, true, true));
        // Each switch by itself.
        let mut off = net.clone();
        off.enable_stun = false;
        assert_eq!(stun_lines(&off, true), vec!["public STUN servers: off"]);
        off.enable_stun = true;
        off.stun_servers.clear();
        assert_eq!(stun_lines(&off, true), vec!["public STUN servers: off"]);
        let mut router = net.clone();
        router.nat_pmp = false;
        assert_eq!(
            router_line(&router, true),
            "router port mapping: UPnP on, NAT-PMP off, PCP on"
        );
        router.upnp = false;
        router.pcp = false;
        assert_eq!(router_line(&router, true), all_off);
        // An edited list: counted, its condition said, no server named.
        let mut edited = net.clone();
        edited
            .stun_servers
            .insert(0, "stun.example.org:3478".to_owned());
        let lines = stun_lines(&edited, true);
        assert_eq!(
            lines,
            vec![
                format!(
                    "public STUN servers: on, {} in the list, one asked per session",
                    n + 1
                ),
                "public STUN servers: not the default list; one operator may be asked by both \
                 computers of a session unless both use the same list"
                    .to_owned(),
            ]
        );
        for line in lines.iter().chain(stun_lines(&net, true).iter()) {
            assert!(
                !line.contains("example") && !line.contains("google"),
                "{line}"
            );
        }
        assert_eq!(leftover_line(0), None);
        assert_eq!(
            leftover_line(3).as_deref(),
            Some("router ports left from an earlier run: 3")
        );
    }

    /// Design `direct` §5.3: the STUN names looked up ahead of the
    /// sessions are those of the roles this process plays, each once, only
    /// while a session may ask a STUN server: an internet build, the policy
    /// `Any` and `enable_stun`. Otherwise none, which empties the cache.
    #[test]
    fn the_stun_names_follow_the_roles_and_the_knobs() {
        let mut cfg = Config::default();
        cfg.network.stun_servers = [
            "stun.a.example:3478",
            "stun2.a.example:3478",
            "stun.b.example:3478",
            "stun.c.example:3478",
        ]
        .map(str::to_owned)
        .to_vec();
        let knobs = DirectKnobs::new(&cfg);
        let viewer = tornect_net::partition(&cfg.network.stun_servers, TornectRole::Viewer);
        let host = tornect_net::partition(&cfg.network.stun_servers, TornectRole::Host);
        assert_eq!(stun_names(&knobs, VIEWER, true), viewer);
        assert_eq!(stun_names(&knobs, HOST, true), host);
        let both = stun_names(&knobs, BOTH, true);
        assert_eq!(both.len(), 4, "{both:?}");
        for entry in &cfg.network.stun_servers {
            assert_eq!(both.iter().filter(|e| *e == entry).count(), 1, "{entry}");
        }
        assert!(stun_names(&knobs, BOTH, false).is_empty());
        // Every rule that keeps STUN from a session keeps the names.
        type Case = (&'static str, fn(&mut Config));
        let quiet: [Case; 4] = [
            ("enable_stun off", |c| c.network.enable_stun = false),
            ("paranoid", |c| c.network.paranoid = true),
            ("lan_only", |c| c.network.lan_only = true),
            ("a bridge", |c| c.tor.bridges = BridgeMode::Snowflake),
        ];
        for (case, set) in quiet {
            let mut cfg = cfg.clone();
            set(&mut cfg);
            assert!(
                stun_names(&DirectKnobs::new(&cfg), BOTH, true).is_empty(),
                "{case}"
            );
        }
        // A bridge Tor went in by after the start.
        knobs.bootstrapped(Rung::Obfs4, &cfg.tor);
        assert!(stun_names(&knobs, BOTH, true).is_empty());
        knobs.bootstrapped(Rung::Direct, &cfg.tor);
        assert_eq!(stun_names(&knobs, VIEWER, true), viewer);
    }

    /// Design `direct` §5.3 and the review of steps B2 and B3: the refresh
    /// starts at the first call, again whenever the names changed (a save,
    /// a bootstrap through a bridge, the other way back), and not for a call
    /// that changes nothing; outside a tokio runtime nothing starts. The
    /// list holds IP literals only, which are never looked up: nothing goes
    /// to a resolver.
    #[tokio::test]
    async fn the_stun_refresh_starts_again_whenever_its_names_change() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path().join("home"));
        let ports = RouterPorts::new(&paths);
        let mut cfg = Config::default();
        cfg.network.stun_servers =
            vec!["192.0.2.1:3478".to_owned(), "198.51.100.1:3478".to_owned()];
        let knobs = DirectKnobs::new(&cfg);
        assert!(ports.follow_stun_in(&knobs, BOTH, true), "the first call");
        assert!(!ports.follow_stun_in(&knobs, BOTH, true), "nothing changed");
        // A save that turns STUN off: an empty list, started again.
        let mut off = cfg.network.clone();
        off.enable_stun = false;
        knobs.set_from(&off);
        assert!(ports.follow_stun_in(&knobs, BOTH, true));
        assert!(!ports.follow_stun_in(&knobs, BOTH, true));
        knobs.set_from(&cfg.network);
        assert!(ports.follow_stun_in(&knobs, BOTH, true), "on again");
        // A bootstrap through a bridge, then plain Tor again.
        knobs.bootstrapped(Rung::Obfs4, &cfg.tor);
        assert!(ports.follow_stun_in(&knobs, BOTH, true));
        knobs.bootstrapped(Rung::Direct, &cfg.tor);
        assert!(ports.follow_stun_in(&knobs, BOTH, true));
        assert!(!ports.follow_stun_in(&knobs, BOTH, true));
        assert!(ports.net().stun_dns().is_empty(), "no literal is cached");
        // Outside a runtime nothing starts, and the next call in one does.
        let other = RouterPorts::new(&paths);
        let (other, started) = std::thread::spawn(move || {
            let started = other.follow_stun_in(&DirectKnobs::new(&Config::default()), BOTH, true);
            (other, started)
        })
        .join()
        .unwrap();
        assert!(!started);
        assert!(other.follow_stun(&knobs, BOTH));
    }

    /// How long a test waits for the router lines' writer.
    const WRITTEN: Duration = Duration::from_secs(10);

    /// Design `direct` §8.1: each router mapping event is one
    /// `router_port` line holding the change and the protocol, fixed words
    /// only, with no session, peer, address or port, in the order the
    /// events came.
    #[test]
    fn router_mapping_events_are_router_port_lines_of_fixed_words() {
        use tornect_net::MapVia;

        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        paths.ensure().unwrap();
        let sink = RouterPortLog::new(&paths);
        sink.on_event(MapEvent::Opened(MapVia::Pcp));
        sink.on_event(MapEvent::Closed(MapVia::Pcp));
        sink.on_event(MapEvent::CloseFailed(MapVia::NatPmp));
        sink.on_event(MapEvent::LeftoverRemoved(MapVia::Upnp));
        assert!(sink.flush(WRITTEN));
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

    /// Review of steps B6 and B7 (§B.8.13): on a host whose store keys
    /// `sessions.log`, the router lines go through the host's one handle,
    /// so each carries the `K_log` tag the verifier asks of every line past
    /// the key's epoch, and they and the lines the FSM writes at the same
    /// moment through that handle stay one chain. A second, unkeyed handle
    /// wrote them untagged (a false tamper badge at every start), and two
    /// handles appending at once could link to the same tail.
    #[test]
    fn router_lines_go_through_the_hosts_keyed_handle_and_keep_its_chain() {
        use tornect_core::session_log::{ChainStatus, line_tag, parse_line_chain};
        use tornect_core::unattended::codec::MasterKey;
        use tornect_net::MapVia;

        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        paths.ensure().unwrap();
        // The host's handle: a line from before the key, then the key (the
        // store's bootstrap) and a first tagged line, the stored head.
        let host = SessionLog::new(paths.sessions_log());
        host.append(&SessionRecord::now(SessionEvent::PairAccepted))
            .unwrap();
        let epoch = host.tail_hash().unwrap();
        let master = MasterKey::generate().unwrap();
        host.set_log_key(Some(master.k_log()));
        let head = host
            .append_chained(&SessionRecord::now(SessionEvent::SessionStarted))
            .unwrap();

        let sink = RouterPortLog::new(&paths);
        sink.attach(host.clone());
        let fsm = {
            let host = host.clone();
            std::thread::spawn(move || {
                for _ in 0..20 {
                    host.append(&SessionRecord::now(SessionEvent::SessionEnded))
                        .unwrap();
                }
            })
        };
        for _ in 0..10 {
            sink.on_event(MapEvent::Opened(MapVia::Pcp));
            sink.on_event(MapEvent::Closed(MapVia::Pcp));
        }
        fsm.join().unwrap();
        assert!(sink.flush(WRITTEN));
        assert_eq!(sink.dropped(), 0);

        let report = host.verify_chain(Some(&head), epoch.as_ref()).unwrap();
        assert_eq!(report.status, ChainStatus::Valid, "{report:?}");
        assert_eq!(report.tagged_beyond_head, 40, "{report:?}");
        let lines = host.read_lines().unwrap();
        let router: Vec<&String> = lines
            .iter()
            .filter(|l| l.contains(r#""event":"router_port""#))
            .collect();
        assert_eq!(router.len(), 20);
        for line in router {
            let chain = parse_line_chain(line).unwrap();
            assert_eq!(
                chain.tag,
                Some(line_tag(&master.k_log(), &chain.without_tag)),
                "{line}"
            );
        }
    }

    /// Review of steps B6 and B7: in a process that runs no host
    /// (`connect`), the router lines are keyed as the host's store keys its
    /// own, from the home's keystore, and they and the process's unattended
    /// connect lines written at the same moment stay one chain (every own
    /// append of the process takes one lock).
    #[test]
    fn router_lines_without_a_host_are_keyed_and_share_the_own_writer() {
        use tornect_core::keystore::{FileSecretStore, SecretStore as _};
        use tornect_core::session_log::{ChainStatus, line_tag, parse_line_chain};
        use tornect_core::trusted::KnownHost;
        use tornect_core::unattended::codec::{MASTER_KEY_ENTRY, MasterKey};
        use tornect_net::MapVia;

        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        paths.ensure().unwrap();
        let master = MasterKey::generate().unwrap();
        FileSecretStore::open(paths.keys_dir())
            .unwrap()
            .put(MASTER_KEY_ENTRY, &master.to_entry())
            .unwrap();

        let sink = RouterPortLog::new(&paths);
        let connects = {
            let paths = paths.clone();
            std::thread::spawn(move || {
                let known = KnownHost {
                    label: "Desk".to_owned(),
                    host_device_pk: [7; 32],
                    paired_at: 1,
                    last_seen: 1,
                };
                for _ in 0..10 {
                    crate::ua_client::log_attempt(
                        &paths,
                        &known,
                        &crate::ua_client::Logged::Ended("unreachable"),
                    );
                }
            })
        };
        for _ in 0..10 {
            sink.on_event(MapEvent::Opened(MapVia::Upnp));
        }
        connects.join().unwrap();
        assert!(sink.flush(WRITTEN));

        let log = SessionLog::new(paths.sessions_log());
        log.set_log_key(Some(master.k_log()));
        let report = log.verify_chain(None, None).unwrap();
        // Every link and tag holds; only the head is the host's to store.
        assert_eq!(report.status, ChainStatus::MissingHead, "{report:?}");
        assert_eq!(report.lines, 20);
        for line in log.read_lines().unwrap() {
            let chain = parse_line_chain(&line).unwrap();
            assert_eq!(
                chain.tag,
                Some(line_tag(&master.k_log(), &chain.without_tag)),
                "{line}"
            );
        }
    }

    /// The mapper's tasks and its mappings' drops hand the line over and
    /// return, whatever the disk does (`MapEvents` must not block): with
    /// the writer stalled, a burst of events returns at once, the queue
    /// keeps [`PORT_LINES_QUEUE`] lines and counts the rest as dropped, and
    /// a flush says the lines are not written yet; once the writer moves,
    /// the kept lines are written in order.
    #[test]
    fn events_never_wait_for_the_disk_and_the_queue_is_bounded() {
        use tornect_net::MapVia;

        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        paths.ensure().unwrap();
        let sink = Arc::new(RouterPortLog::new(&paths));
        let stalled = crate::ua_client::hold_own_appends();
        let (done_tx, done) = std::sync::mpsc::channel();
        {
            let sink = Arc::clone(&sink);
            std::thread::spawn(move || {
                for _ in 0..100 {
                    sink.on_event(MapEvent::Opened(MapVia::Pcp));
                }
                let _ = done_tx.send(());
            });
        }
        done.recv_timeout(WRITTEN)
            .expect("the events returned while the writer was stalled");
        assert!(
            !sink.flush(Duration::from_millis(50)),
            "nothing written yet"
        );
        drop(stalled);
        assert!(sink.flush(WRITTEN));
        let written = SessionLog::new(paths.sessions_log()).read_all().unwrap();
        // The writer may have taken the first line in hand before the queue
        // filled.
        assert!(
            (PORT_LINES_QUEUE..=PORT_LINES_QUEUE + 1).contains(&written.len()),
            "{}",
            written.len()
        );
        assert_eq!(u64::try_from(written.len()).unwrap() + sink.dropped(), 100);
        assert!(written.iter().all(|r| r.event == SessionEvent::RouterPort));
    }

    /// Design `direct` §8.6, review of steps B6 and B7: the host's handle,
    /// once given, carries every router line from then on, and the sweep
    /// starts with it; the sweep starts once per process, so a window whose
    /// host role was wired does not start a second one. The machine has the
    /// router ledger (only a machine with one starts a sweep), and the
    /// lifecycle a command runs in returns what the command returned only
    /// once the releases running at its end are done and their lines are
    /// on disk.
    #[tokio::test]
    async fn the_router_lifecycle_sweeps_once_and_waits_for_releases_and_lines_at_exit() {
        use tornect_net::MapVia;

        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        paths.ensure().unwrap();
        let ports = RouterPorts::new(&paths);
        let sweep = ports.net().sweep_leftovers().expect("a router ledger");
        assert_eq!(sweep.await.unwrap(), tornect_net::SweepReport::default());
        assert!(
            RealNet::new().sweep_leftovers().is_none(),
            "no ledger, no sweep"
        );
        let host = SessionLog::new(paths.sessions_log());
        ports.hosting(&host);
        assert!(format!("{:?}", ports.log()).contains("attached: true"));
        assert!(!ports.sweep(), "one sweep per process");
        ports.not_hosting();
        assert!(!ports.sweep());

        let releases = ports.net().releases();
        let started = std::time::Instant::now();
        let log = Arc::clone(ports.log());
        let out = router_lifecycle(&ports, async {
            releases.spawn(
                &tokio::runtime::Handle::current(),
                Box::pin(async move {
                    tokio::time::sleep(Duration::from_millis(150)).await;
                    log.on_event(MapEvent::Closed(MapVia::Pcp));
                }),
            );
            7
        })
        .await;
        assert_eq!(out, 7);
        assert_eq!(releases.running(), 0, "the release ended before the exit");
        assert!(started.elapsed() >= Duration::from_millis(150));
        let lines = host.read_all().unwrap();
        assert_eq!(lines.len(), 1, "the release's line is on disk");
        assert_eq!(lines[0].detail.as_deref(), Some("closed pcp"));
        // Nothing to release or write: the end returns at once.
        let started = std::time::Instant::now();
        assert!(ports.wind_down().await);
        assert!(started.elapsed() < SHUTDOWN_RELEASE_WAIT);
    }
}
