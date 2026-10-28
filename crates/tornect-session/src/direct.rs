//! The session layer's side of the direct path (the direct design §4,
//! §6.5–§6.7, §8.5): what a stream of a session's direct QUIC connection
//! must offer [`MediaHost::serve_direct`](crate::MediaHost::serve_direct),
//! the host's half of the path phase ([`DirectHost`]), the viewer's
//! ([`ViewerDirect::choose_path`], from its [`decide`]), the reasons a
//! session's media is relayed through Tor ([`TorWhy`], [`FallbackWhy`],
//! [`PathEnd`]), the settings both halves read ([`DirectSettings`]), the
//! candidates' wire form ([`to_wire`], [`from_wire`]), the hook a second
//! stream of the connection is served through ([`SecondStream`]), and the
//! viewer's one fallback after its direct `Bind` ([`after_bind_close`]).

use std::fmt;
use std::future::Future;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tornect_core::DeviceId;
use tornect_core::config::Network;
use tornect_core::session_log::TransportKind;
use tornect_net::{BoxFuture, Established, GatherConfig, MapProtocols, QuicStream, TornectRole};
use zeroize::Zeroizing;

mod decide;
mod host;
mod viewer;
mod wire;

pub use decide::{Decision, FallbackWhy, Mine, PathEnd, TorWhy, decide};
pub use host::{DirectHost, DirectHostStats, OnMedia};
pub use viewer::{
    DirectBindFailed, DirectMedia, DirectServices, PathChoice, ViewerDirect, ViewerDirectStats,
};
pub use wire::{from_wire, to_wire};

/// Whether a session may reach beyond the same site (the direct design
/// §4): public addresses, server-reflexive and mapped candidates. Off in
/// Phase A, so both sides' scope is always
/// [`Scope::SameSite`](tornect_net::Scope::SameSite); Phase B
/// turns it on once its gathering and its tests land.
pub const INTERNET_DIRECT: bool = false;

/// The quinn send priority of a direct connection's media stream, on both
/// ends (the direct design §6.7): higher is sent first, so the viewer's
/// input and acks and the host's pictures go before a file's bytes.
pub(crate) const MEDIA_PRIORITY: i32 = 1;

/// The quinn send priority of a direct connection's services stream, on
/// both ends (the direct design §6.7).
pub(crate) const SERVICES_PRIORITY: i32 = 0;

/// How long the host keeps a session's direct link open from its bind
/// without a direct claim (the direct design §4): the largest
/// `punch_timeout` plus 10 s for Tor's delay and the viewer's commit, so the
/// host never stops listening while the viewer still punches. A link with
/// no `Bind` by then is closed; a `lan_only` session then ends
/// `BYE{NO_LAN_PATH}`.
pub const HOST_DIRECT_LINGER: Duration = Duration::from_secs(20);

/// How long the host waits, once a direct media stream was served to its
/// end, for the viewer to close the connection before closing it itself: the
/// last frames written (the media `Close` among them) reach the viewer
/// instead of being cut off by the endpoint's close.
pub const DIRECT_DRAIN: Duration = Duration::from_secs(2);

/// The least `network.punch_timeout_ms` the direct path uses (the direct
/// design §4): `Config::validate` refuses a file below it, and options built
/// any other way are raised to it.
pub const PUNCH_TIMEOUT_MIN_MS: u32 = tornect_core::config::PUNCH_TIMEOUT_MIN_MS;

/// The most `network.punch_timeout_ms` the direct path uses, under the
/// host's [`HOST_DIRECT_LINGER`]: `Config::validate` refuses a file above
/// it, and options built any other way are lowered to it.
pub const PUNCH_TIMEOUT_MAX_MS: u32 = tornect_core::config::PUNCH_TIMEOUT_MAX_MS;

// The linger outlasts the longest punch by 10 s (the direct design §4).
const _: () = assert!(HOST_DIRECT_LINGER.as_secs() >= PUNCH_TIMEOUT_MAX_MS as u64 / 1000 + 10);

// A fixed `network.direct_port` that `Config::validate` lets through is one
// the peer's `RemoteFilter` admits.
const _: () = assert!(tornect_core::config::MIN_DIRECT_PORT == tornect_net::addr::MIN_REMOTE_PORT);

/// What the direct path is run with, from `[network]` (the direct design
/// §8.5 `DirectOptions`).
#[derive(Clone, PartialEq, Eq)]
pub struct DirectOptions {
    /// `network.direct_port`: the session socket's port when it is free.
    pub direct_port: Option<u16>,
    /// The viewer's hard cap from the accept to "direct ready":
    /// `network.punch_timeout_ms`, kept within [`PUNCH_TIMEOUT_MIN_MS`] and
    /// [`PUNCH_TIMEOUT_MAX_MS`].
    pub punch_timeout: Duration,
    /// The viewer's part of `network.stun_servers`
    /// ([`tornect_net::partition`], decision M1-81).
    pub stun_partition_viewer: Arc<[String]>,
    /// The host's part: no operator is in both.
    pub stun_partition_host: Arc<[String]>,
    /// `network.enable_stun`.
    pub enable_stun: bool,
    /// `network.upnp`, `network.nat_pmp` and `network.pcp`.
    pub map: MapProtocols,
}

impl fmt::Debug for DirectOptions {
    /// The servers' count only: the list is the user's.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectOptions")
            .field("direct_port", &self.direct_port.is_some())
            .field("punch_timeout", &self.punch_timeout)
            .field("stun_servers_viewer", &self.stun_partition_viewer.len())
            .field("stun_servers_host", &self.stun_partition_host.len())
            .field("enable_stun", &self.enable_stun)
            .field("map", &self.map)
            .finish()
    }
}

impl Default for DirectOptions {
    fn default() -> Self {
        Self::from_network(&Network::default())
    }
}

impl DirectOptions {
    /// The options `net` asks for, its punch timeout kept within
    /// [`PUNCH_TIMEOUT_MIN_MS`]`..=`[`PUNCH_TIMEOUT_MAX_MS`].
    #[must_use]
    pub fn from_network(net: &Network) -> Self {
        let punch_ms = net
            .punch_timeout_ms
            .clamp(PUNCH_TIMEOUT_MIN_MS, PUNCH_TIMEOUT_MAX_MS);
        Self {
            direct_port: net.direct_port,
            punch_timeout: Duration::from_millis(u64::from(punch_ms)),
            stun_partition_viewer: tornect_net::partition(&net.stun_servers, TornectRole::Viewer)
                .into(),
            stun_partition_host: tornect_net::partition(&net.stun_servers, TornectRole::Host)
                .into(),
            enable_stun: net.enable_stun,
            map: MapProtocols {
                upnp: net.upnp,
                nat_pmp: net.nat_pmp,
                pcp: net.pcp,
            },
        }
    }

    /// What `role`'s side may gather in internet scope: its part of the
    /// STUN list, `enable_stun` and the router protocols.
    #[must_use]
    pub fn gather(&self, role: TornectRole) -> GatherConfig {
        GatherConfig {
            stun_partition: match role {
                TornectRole::Viewer => Arc::clone(&self.stun_partition_viewer),
                TornectRole::Host => Arc::clone(&self.stun_partition_host),
            },
            use_stun: self.enable_stun,
            map: self.map,
        }
    }
}

/// The direct path's options as the settings change them (the direct design
/// §8.5 `DirectSettings`): clones share one value, and each session reads it
/// once, when its path starts.
#[derive(Debug, Clone, Default)]
pub struct DirectSettings(Arc<RwLock<DirectOptions>>);

impl DirectSettings {
    /// Settings holding `options`.
    #[must_use]
    pub fn new(options: DirectOptions) -> Self {
        Self(Arc::new(RwLock::new(options)))
    }

    /// Settings holding what `net` asks for ([`DirectOptions::from_network`]).
    #[must_use]
    pub fn from_network(net: &Network) -> Self {
        Self::new(DirectOptions::from_network(net))
    }

    /// From now on, what `net` asks for; sessions already on their path keep
    /// what they read.
    pub fn set_from(&self, net: &Network) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = DirectOptions::from_network(net);
    }

    /// The current options.
    #[must_use]
    pub fn get(&self) -> DirectOptions {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

/// The host's hook for the second stream of a session's direct connection
/// (the direct design §6.7): the services stream, which
/// [`ServicesHost::second_stream`](crate::services::ServicesHost::second_stream)
/// serves. [`DirectHost`] accepts that stream only after the session's
/// media was claimed on this connection, sets its send priority to 0
/// (below the media stream's 1) and serves it on its own task beside the
/// media stream, neither waiting on the other. The session's end (which a
/// kill and an end of the viewer's device set) ends it as it ends the
/// media stream, and the link stays until both ended, within
/// [`DIRECT_DRAIN`]; a link closed under it ends it through its I/O. The
/// future [`Self::serve`] returns is always run to its end, so it may
/// rely on its own teardown. A host without one never accepts a second
/// stream: the viewer's waits unread, within the stream window
/// ([`tornect_net::quic::HOST_STREAMS`]).
pub trait SecondStream: Send + Sync {
    /// Serve `stream` for session `expected_session`, on a connection whose
    /// TLS proved the device `peer`, whose exporter output is `ekm` (what
    /// the stream's own `Bind` MAC covers) and whose path is `route`
    /// ([`TransportKind::Lan`] or [`TransportKind::Direct`], as the media
    /// stream's claim on it says).
    fn serve(
        &self,
        stream: QuicStream,
        expected_session: String,
        peer: DeviceId,
        ekm: Zeroizing<[u8; 32]>,
        route: TransportKind,
    ) -> BoxFuture<'static, ()>;
}

/// A bidirectional stream of a session's direct connection, as the media
/// host serves it: [`tornect_net::QuicStream`] in production, a pipe in
/// tests.
pub trait DirectStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {
    /// The host's refusal of a `Bind` (the direct design §6.5): write
    /// `frame` (an encoded `BindRefused`), finish the stream, give the
    /// viewer a bounded moment to read it, then close the connection with
    /// `code`, a `tornect_proto::reason` code. Dropping the future closes at
    /// once.
    fn refuse(self, frame: Vec<u8>, code: u16) -> impl Future<Output = ()> + Send;
}

impl DirectStream for QuicStream {
    async fn refuse(self, frame: Vec<u8>, code: u16) {
        QuicStream::refuse(self, &frame, code).await;
    }
}

/// What the viewer does once [`MediaViewer::bind`](crate::MediaViewer::bind)
/// failed on the direct path ([`after_bind_close`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AfterBind {
    /// The host refused this connection's TLS handshake before sending a
    /// stream byte, so it never read the `Bind` and cannot have claimed the
    /// session: send `TOR_FALLBACK{QUIC}` and bind onion media.
    Fallback,
    /// The `Bind` may have reached the host: the commit point has passed
    /// and the session's media ends (decision M1-79).
    End,
}

/// Whether a viewer whose direct `Bind` failed on `link` may still fall
/// back to the onion path (the direct design §4, §8.5; decision M1-79's
/// one exception to the commit point): only when the connection was closed by a
/// TLS alert ([`Established::closed_by_crypto`]) before any host stream
/// byte arrived. Anything else — a refusal, a wrong proof, a timeout, a
/// close after the host wrote — is [`AfterBind::End`].
///
/// The direct design passes the viewer's [`DirectMedia`], whose stream the
/// bind consumed; its link is the part this reads
/// ([`DirectMedia::bind`] asks it).
#[must_use]
pub fn after_bind_close(link: &Established) -> AfterBind {
    after_close(link.closed_by_crypto(), link.stream_bytes_received())
}

/// [`after_bind_close`]'s decision from the link's two readings.
fn after_close(closed_by_crypto: bool, host_bytes: u64) -> AfterBind {
    if closed_by_crypto && host_bytes == 0 {
        AfterBind::Fallback
    } else {
        AfterBind::End
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use tornect_net::{Candidate, CandidateKind, Scope};
    use tornect_signal::messages::Body as _;
    use tornect_signal::messages::{self, candidate_kind, scope};

    fn candidate(kind: CandidateKind, addr: &str) -> Candidate {
        Candidate {
            kind,
            addr: addr.parse().unwrap(),
        }
    }

    /// The wire form round-trips: kinds, IPv4 as 4 bytes, IPv6 as 16, the
    /// scope in every frame, at most eight candidates a frame, and every
    /// frame valid as the FSM checks it.
    #[test]
    fn candidates_round_trip_through_the_wire_form() {
        let mut batch: Vec<Candidate> = (1..=9u8)
            .map(|i| candidate(CandidateKind::Host, &format!("192.168.1.{i}:4000")))
            .collect();
        batch.push(candidate(CandidateKind::Srflx, "[2001:db8::1]:5000"));
        batch.push(candidate(CandidateKind::Mapped, "203.0.113.7:6000"));
        for scope in [Scope::SameSite, Scope::Internet] {
            let frames = to_wire(&batch, scope);
            assert_eq!(
                frames
                    .iter()
                    .map(|f| f.candidates.len())
                    .collect::<Vec<_>>(),
                [8, 3]
            );
            let mut back = Vec::new();
            for frame in &frames {
                frame.validate().expect("a valid frame");
                let (candidates, got) = from_wire(frame);
                assert_eq!(got, scope);
                back.extend(candidates);
            }
            assert_eq!(back, batch);
        }
        let frames = to_wire(&batch[..1], Scope::SameSite);
        assert_eq!(frames[0].candidates[0].ip, vec![192, 168, 1, 1]);
        assert_eq!(frames[0].scope, Some(scope::SAME_SITE));
        assert!(to_wire(&[], Scope::SameSite).is_empty());
    }

    /// What never goes on the wire: a peer-reflexive candidate (local
    /// only) and port 0; a v4-mapped address goes as its 4 IPv4 bytes.
    #[test]
    fn prflx_and_port_zero_are_never_sent_and_v4_mapped_goes_as_ipv4() {
        let batch = [
            candidate(CandidateKind::Prflx, "192.168.1.9:4000"),
            candidate(CandidateKind::Host, "192.168.1.10:0"),
            candidate(CandidateKind::Host, "[::ffff:192.168.1.11]:4000"),
        ];
        let frames = to_wire(&batch, Scope::SameSite);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].candidates.len(), 1);
        assert_eq!(frames[0].candidates[0].ip, vec![192, 168, 1, 11]);
        let (back, _) = from_wire(&frames[0]);
        assert_eq!(back, [candidate(CandidateKind::Host, "192.168.1.11:4000")]);
    }

    /// What a receiver drops: an unknown kind, a v4-mapped IPv6 address,
    /// an address of another length, port 0; an absent or unknown scope is
    /// same-site, and only the internet code is the internet scope.
    #[test]
    fn unknown_kinds_and_malformed_addresses_are_dropped() {
        let wire = |kind, ip: Vec<u8>, port| messages::Candidate { kind, ip, port };
        let mut mapped = vec![0; 10];
        mapped.extend([0xff, 0xff, 192, 168, 1, 1]);
        let frame = |scope| messages::Candidates {
            candidates: vec![
                wire(7, vec![192, 168, 1, 1], 4000),
                wire(candidate_kind::HOST, mapped.clone(), 4000),
                wire(candidate_kind::HOST, vec![192, 168, 1], 4000),
                wire(candidate_kind::HOST, vec![192, 168, 1, 2], 0),
                wire(candidate_kind::HOST, vec![192, 168, 1, 3], 4000),
            ],
            scope,
        };
        for (scope, want) in [
            (None, Scope::SameSite),
            (Some(scope::SAME_SITE), Scope::SameSite),
            (Some(scope::INTERNET), Scope::Internet),
            (Some(9), Scope::SameSite),
        ] {
            let (batch, got) = from_wire(&frame(scope));
            assert_eq!(got, want);
            assert_eq!(batch, [candidate(CandidateKind::Host, "192.168.1.3:4000")]);
        }
    }

    /// `punch_timeout_ms` is kept within 1–10 s, under the host's linger;
    /// the settings' clones share one value.
    #[test]
    fn the_punch_timeout_is_kept_within_its_bounds_and_settings_are_shared() {
        let net = |ms| Network {
            punch_timeout_ms: ms,
            direct_port: Some(4100),
            ..Network::default()
        };
        for (ms, want) in [
            (1, 1000),
            (999, 1000),
            (4000, 4000),
            (10_000, 10_000),
            (60_000, 10_000),
        ] {
            let options = DirectOptions::from_network(&net(ms));
            assert_eq!(options.punch_timeout, Duration::from_millis(want));
            assert_eq!(options.direct_port, Some(4100));
            assert!(options.punch_timeout < HOST_DIRECT_LINGER);
        }
        assert_eq!(
            DirectOptions::default().punch_timeout,
            Duration::from_secs(4)
        );
        let settings = DirectSettings::default();
        let shared = settings.clone();
        settings.set_from(&net(2500));
        assert_eq!(shared.get().punch_timeout, Duration::from_millis(2500));
        assert_eq!(shared.get().direct_port, Some(4100));
    }

    /// Design `direct` §5.3, §7.3, §7.4 (decision M1-81): each role gathers
    /// with its own part of `stun_servers`, no operator in both, with
    /// `enable_stun` and the router protocols as `[network]` says; `Debug`
    /// counts the servers and never names one.
    #[test]
    fn each_role_gathers_with_its_part_of_the_stun_list_and_the_router_switches() {
        let net = Network {
            stun_servers: vec![
                "stun.cloudflare.com:3478".to_owned(),
                "stun.l.google.com:19302".to_owned(),
                "stun1.l.google.com:19302".to_owned(),
                "stun.example.org:3478".to_owned(),
            ],
            enable_stun: false,
            upnp: false,
            nat_pmp: true,
            pcp: true,
            ..Network::default()
        };
        let options = DirectOptions::from_network(&net);
        let viewer = options.gather(TornectRole::Viewer);
        let host = options.gather(TornectRole::Host);
        assert_eq!(
            *viewer.stun_partition,
            *tornect_net::partition(&net.stun_servers, TornectRole::Viewer)
        );
        assert_eq!(
            *host.stun_partition,
            *tornect_net::partition(&net.stun_servers, TornectRole::Host)
        );
        assert!(!viewer.stun_partition.is_empty() && !host.stun_partition.is_empty());
        let google = |list: &[String]| list.iter().any(|s| s.contains(".l.google.com"));
        assert!(
            google(&viewer.stun_partition) != google(&host.stun_partition),
            "one operator's servers stay on one side"
        );
        for side in [&viewer, &host] {
            assert!(!side.use_stun);
            assert_eq!(
                side.map,
                MapProtocols {
                    upnp: false,
                    nat_pmp: true,
                    pcp: true
                }
            );
        }
        let defaults = DirectOptions::default().gather(TornectRole::Viewer);
        assert_eq!(defaults.use_stun, Network::default().enable_stun);
        let shown = format!("{options:?}");
        assert!(
            !shown.contains("stun.") && !shown.contains("3478"),
            "{shown}"
        );
    }

    /// Decision M1-79: only a TLS-alert close with no host stream byte falls
    /// back; a byte from the host, or any other close, ends the media.
    #[test]
    fn only_a_crypto_close_before_any_host_byte_falls_back() {
        assert_eq!(after_close(true, 0), AfterBind::Fallback);
        assert_eq!(after_close(true, 1), AfterBind::End);
        assert_eq!(after_close(true, 37), AfterBind::End);
        assert_eq!(after_close(false, 0), AfterBind::End);
        assert_eq!(after_close(false, 37), AfterBind::End);
    }
}
