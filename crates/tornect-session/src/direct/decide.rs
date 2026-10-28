//! What a viewer does with a session's direct path, decided from the
//! accept alone (the direct design §4 "`decide`", §3.1 "Reasons"; decisions
//! M1-79, M1-85, M1-86): [`decide`] and its [`Decision`], the reasons a
//! session is relayed through Tor ([`TorWhy`], [`FallbackWhy`]) and how a
//! session's media path ended ([`PathEnd`]).
//!
//! These types are the one source of truth for what the window and the CLI
//! say about a session's route: the copy and the CLI names are functions of
//! them only.

use tornect_net::{Route, Scope};
use tornect_signal::consent::{TransportKnob, TransportPolicy};
use tornect_signal::messages::fallback;

use super::INTERNET_DIRECT;

/// This viewer's own effective policy (the direct design §4 `mine`): its
/// privacy switches, the bridge rule (decision M1-86) and `--tor-only`, and
/// whether the bridge rule alone made it `tor_only`, which changes the
/// reason the window gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mine {
    /// The effective policy.
    pub policy: TransportPolicy,
    /// `policy` is `tor_only` only because Tor reaches the network through
    /// a bridge: the reason is [`TorWhy::Bridge`], not [`TorWhy::HereOff`].
    pub bridged: bool,
}

impl Mine {
    /// The policy `knob` gives now ([`TransportKnob::get`]), the bridge rule
    /// included.
    #[must_use]
    pub fn from_knob(knob: &TransportKnob) -> Self {
        let policy = knob.get();
        Self {
            policy,
            bridged: policy == TransportPolicy::TorOnly && knob.off_by_bridge(),
        }
    }

    /// `policy`, set by this computer's own settings (or `--tor-only`, which
    /// is [`TransportPolicy::TorOnly`] for one session).
    #[must_use]
    pub const fn of(policy: TransportPolicy) -> Self {
        Self {
            policy,
            bridged: false,
        }
    }
}

/// Why a session's media is relayed through Tor (the direct design §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TorWhy {
    /// The host signed `tor_only` (its paranoid mode, the bridge rule, or an
    /// unattended grant's Tor-only requirement), or declined with `OFF`.
    HostPolicy,
    /// Direct connections are off on this computer (or `--tor-only`).
    HereOff,
    /// Direct connections are off here while Tor uses a bridge (decision
    /// M1-86).
    Bridge,
    /// The host's build cannot connect directly (no `dir1`).
    OldHost,
    /// This computer is connecting to itself (the two device keys are
    /// equal, decision M1-80).
    SameDevice,
    /// The direct attempt failed, or could not start.
    Fallback(FallbackWhy),
}

/// Why a direct attempt ended in the Tor fallback (the direct design §3.1,
/// `TorWhy::Fallback`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FallbackWhy {
    /// This computer has no address a direct connection can use.
    HereNoAddresses,
    /// The host has no address a direct connection can use.
    HostNoAddresses,
    /// This computer could not open its session socket.
    HereSocket,
    /// The host could not open its session socket.
    HostSocket,
    /// Nothing came from the host in time: no path frame, no probe.
    HostSilent,
    /// No round trip of this side's was validated.
    NoPath {
        /// The host's authenticated probe requests arrived (its firewall
        /// may be blocking ours).
        heard: bool,
    },
    /// An address was validated, then QUIC, the peer check, the TLS pin or
    /// opening the stream failed.
    Quic,
}

impl TorWhy {
    /// The reason's name on the CLI (`ROUTE tor <name>`, the direct design
    /// §3.1).
    #[must_use]
    pub const fn cli_name(self) -> &'static str {
        match self {
            Self::HostPolicy => "policy",
            Self::HereOff => "here-off",
            Self::Bridge => "bridge",
            Self::OldHost => "old-host",
            Self::SameDevice => "same-device",
            Self::Fallback(why) => why.cli_name(),
        }
    }

    /// How the viewer reads the host's own `TOR_FALLBACK{reason}` (the
    /// direct design §4, §6.1): `OFF` is the host's policy, `NO_ADDRESSES`
    /// and `SOCKET` the host's addresses and socket; any other reason, or
    /// none, is an unknown one, read as [`FallbackWhy::NoPath`] without
    /// `heard`.
    #[must_use]
    pub const fn from_host_reason(reason: Option<u32>) -> Self {
        match reason {
            Some(fallback::OFF) => Self::HostPolicy,
            Some(fallback::NO_ADDRESSES) => Self::Fallback(FallbackWhy::HostNoAddresses),
            Some(fallback::SOCKET) => Self::Fallback(FallbackWhy::HostSocket),
            _ => Self::Fallback(FallbackWhy::NoPath { heard: false }),
        }
    }

    /// The `TOR_FALLBACK` reason the viewer sends for a session relayed for
    /// this reason (`None`: `TOR_FALLBACK{}`, the bytes `A0` an old host
    /// is sent). A reason the host gave first is answered `PEER_OFF`.
    /// [`decide`] says `OFF` instead when this viewer's own policy is
    /// `tor_only` too.
    #[must_use]
    pub const fn code(self) -> Option<u32> {
        match self {
            Self::HostPolicy => Some(fallback::PEER_OFF),
            Self::HereOff | Self::Bridge | Self::SameDevice => Some(fallback::OFF),
            Self::OldHost => None,
            Self::Fallback(why) => Some(why.code()),
        }
    }
}

impl FallbackWhy {
    /// The reason's name on the CLI (the direct design §3.1).
    #[must_use]
    pub const fn cli_name(self) -> &'static str {
        match self {
            Self::HereNoAddresses => "here-no-addresses",
            Self::HostNoAddresses => "host-no-addresses",
            Self::HereSocket => "here-socket",
            Self::HostSocket => "host-socket",
            Self::HostSilent => "host-silent",
            Self::NoPath { heard: false } => "no-path",
            Self::NoPath { heard: true } => "no-path-firewall",
            Self::Quic => "quic",
        }
    }

    /// The `TOR_FALLBACK` reason the viewer sends for it. A host that
    /// declined first (its own `NO_ADDRESSES` or `SOCKET`) is answered
    /// `PEER_OFF`: those two codes name the sender's own addresses and
    /// socket.
    #[must_use]
    pub const fn code(self) -> u32 {
        match self {
            Self::HereNoAddresses => fallback::NO_ADDRESSES,
            Self::HereSocket => fallback::SOCKET,
            Self::HostNoAddresses | Self::HostSocket => fallback::PEER_OFF,
            Self::HostSilent => fallback::PEER_SILENT,
            Self::NoPath { .. } => fallback::NO_PATH,
            Self::Quic => fallback::QUIC,
        }
    }
}

/// How a session's media path ended, for the window and the CLI (the direct
/// design §3.1, §3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathEnd {
    /// The media runs on the direct connection.
    Direct(Route),
    /// The media is relayed through Tor.
    Tor(TorWhy),
    /// The session carries no media (`connect --no-video`).
    NoMedia,
    /// A `lan_only` session found no same-site path and ends
    /// `BYE{NO_LAN_PATH}` (decision M1-85).
    LanRefused,
}

impl PathEnd {
    /// The words after `ROUTE` on the CLI (the direct design §3.5):
    /// `direct lan`, `direct lan ipv6`, `direct internet`,
    /// `direct internet ipv6`, `tor <reason>`, `none`, `none no-lan-path`.
    #[must_use]
    pub fn route_words(&self) -> String {
        match self {
            Self::Direct(route) => format!(
                "direct {}{}",
                if route.same_site { "lan" } else { "internet" },
                if route.ipv6 { " ipv6" } else { "" }
            ),
            Self::Tor(why) => format!("tor {}", why.cli_name()),
            Self::NoMedia => "none".to_owned(),
            Self::LanRefused => "none no-lan-path".to_owned(),
        }
    }
}

/// What the viewer does with a session's path, decided before it touches
/// the network ([`decide`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Try the direct path with candidates of `scope`. When it fails, a
    /// `lan_only` session ends `BYE{NO_LAN_PATH}`; any other falls back to
    /// Tor.
    Try {
        /// The scope of this side's candidates, sent in every `CANDIDATES`.
        scope: Scope,
        /// Either side's policy is `lan_only`: no Tor media fallback.
        lan_only: bool,
    },
    /// Send `TOR_FALLBACK{reason}` (`None`: `TOR_FALLBACK{}`) and use the
    /// onion media stream; nothing is revealed.
    Tor {
        /// The reason sent.
        reason: Option<u32>,
        /// Why, for the window and the CLI.
        why: TorWhy,
    },
    /// The session carries no media: send `TOR_FALLBACK{NO_MEDIA}`.
    NoMedia,
    /// End the session `BYE{NO_LAN_PATH}` with nothing revealed: a
    /// `lan_only` session that can have no same-site path.
    LanRefused,
}

/// The viewer's decision for a session (the direct design §4 "`decide`"):
/// `p_h` is the policy the host signed in `SESSION_ACCEPT`, `mine` this
/// computer's own, `media` whether the session carries media at all,
/// `host_dir1` whether the host's signed `HELLO_ACK` announced
/// `feats::DIR1`, `same_key` whether the host's device key is this
/// computer's own. The rules apply in order:
///
/// 1. no media → [`Decision::NoMedia`], whatever the policies;
/// 2. an old host → `TOR_FALLBACK{}` ([`TorWhy::OldHost`]), or
///    [`Decision::LanRefused`] when either side is `lan_only`;
/// 3. the same device → `TOR_FALLBACK{OFF}` ([`TorWhy::SameDevice`]), or
///    [`Decision::LanRefused`] when either side is `lan_only`;
/// 4. the policy table: a `tor_only` side and a `lan_only` side have no
///    path in common ([`Decision::LanRefused`]); a host's `tor_only` is
///    [`TorWhy::HostPolicy`] (`PEER_OFF`, or `OFF` when this side is
///    `tor_only` too); this side's own `tor_only` is [`TorWhy::HereOff`]
///    or [`TorWhy::Bridge`] (`OFF`); otherwise the path is tried, within
///    the same site when either side is `lan_only` or the build has no
///    internet scope ([`INTERNET_DIRECT`]).
///
/// In rules 2 and 3 a host that signed `lan_only` refuses Tor media just
/// as this side's own `lan_only` does (decision M1-85): neither an old
/// host nor this same device can have a same-site path, so the session
/// ends with nothing revealed instead of binding an onion stream the host
/// promised not to serve. The design's text names only this side's policy
/// there.
#[must_use]
pub fn decide(
    p_h: TransportPolicy,
    mine: Mine,
    media: bool,
    host_dir1: bool,
    same_key: bool,
) -> Decision {
    decide_with(INTERNET_DIRECT, p_h, mine, media, host_dir1, same_key)
}

/// [`decide`] with the internet scope given: tests build either scope,
/// whatever the constant says (the direct design §2).
pub(crate) fn decide_with(
    internet: bool,
    p_h: TransportPolicy,
    mine: Mine,
    media: bool,
    host_dir1: bool,
    same_key: bool,
) -> Decision {
    use TransportPolicy::{Any, LanOnly, TorOnly};
    let lan_only = mine.policy == LanOnly || p_h == LanOnly;
    if !media {
        return Decision::NoMedia;
    }
    if !host_dir1 {
        return if lan_only {
            Decision::LanRefused
        } else {
            Decision::Tor {
                reason: None,
                why: TorWhy::OldHost,
            }
        };
    }
    if same_key {
        return if lan_only {
            Decision::LanRefused
        } else {
            Decision::Tor {
                reason: Some(fallback::OFF),
                why: TorWhy::SameDevice,
            }
        };
    }
    match (p_h, mine.policy) {
        (TorOnly, LanOnly) | (LanOnly, TorOnly) => Decision::LanRefused,
        (TorOnly, Any) => Decision::Tor {
            reason: Some(fallback::PEER_OFF),
            why: TorWhy::HostPolicy,
        },
        (TorOnly, TorOnly) => Decision::Tor {
            reason: Some(fallback::OFF),
            why: TorWhy::HostPolicy,
        },
        (Any, TorOnly) => Decision::Tor {
            reason: Some(fallback::OFF),
            why: if mine.bridged {
                TorWhy::Bridge
            } else {
                TorWhy::HereOff
            },
        },
        (Any, Any) => Decision::Try {
            scope: if internet {
                Scope::Internet
            } else {
                Scope::SameSite
            },
            lan_only: false,
        },
        (Any | LanOnly, LanOnly) | (LanOnly, Any) => Decision::Try {
            scope: Scope::SameSite,
            lan_only: true,
        },
    }
}

#[cfg(test)]
mod tests {
    use tornect_core::config::Network;

    use super::*;

    const ANY: TransportPolicy = TransportPolicy::Any;
    const TOR: TransportPolicy = TransportPolicy::TorOnly;
    const LAN: TransportPolicy = TransportPolicy::LanOnly;

    fn tor(reason: Option<u32>, why: TorWhy) -> Decision {
        Decision::Tor { reason, why }
    }

    /// The policy table of the direct design §4, every cell, in either
    /// scope: what is tried, what is said, what ends.
    fn table(internet: bool) -> [(TransportPolicy, TransportPolicy, Decision); 9] {
        let same_site = |lan_only| Decision::Try {
            scope: Scope::SameSite,
            lan_only,
        };
        let any_any = Decision::Try {
            scope: if internet {
                Scope::Internet
            } else {
                Scope::SameSite
            },
            lan_only: false,
        };
        [
            (ANY, ANY, any_any),
            (ANY, TOR, tor(Some(fallback::OFF), TorWhy::HereOff)),
            (ANY, LAN, same_site(true)),
            (TOR, ANY, tor(Some(fallback::PEER_OFF), TorWhy::HostPolicy)),
            (TOR, TOR, tor(Some(fallback::OFF), TorWhy::HostPolicy)),
            (TOR, LAN, Decision::LanRefused),
            (LAN, ANY, same_site(true)),
            (LAN, TOR, Decision::LanRefused),
            (LAN, LAN, same_site(true)),
        ]
    }

    /// The policy table of the direct design §4, every cell, with and
    /// without the internet scope.
    #[test]
    fn the_policy_table_is_the_designs() {
        for internet in [false, true] {
            for (p_h, mine, want) in table(internet) {
                assert_eq!(
                    decide_with(internet, p_h, Mine::of(mine), true, true, false),
                    want,
                    "host {p_h:?}, viewer {mine:?}, internet {internet}"
                );
            }
        }
    }

    /// The build's own scope (step B12 turned it on): [`decide`] gives the
    /// internet-scope table in every cell, so a build with
    /// [`INTERNET_DIRECT`] off fails the `(Any, Any)` cell.
    #[test]
    fn this_build_decides_in_the_internet_scope() {
        for (p_h, mine, want) in table(true) {
            assert_eq!(
                decide(p_h, Mine::of(mine), true, true, false),
                want,
                "host {p_h:?}, viewer {mine:?}"
            );
        }
    }

    /// Rules 1–3 come before the table (the direct design §4): no media is
    /// `NO_MEDIA` whatever the policies; an old host is sent
    /// `TOR_FALLBACK{}` and the same device `TOR_FALLBACK{OFF}`, except
    /// that the session ends instead when either side is `lan_only` (a
    /// `lan_only` host's signed policy refuses Tor media as the viewer's
    /// own does, decision M1-85); the bridge rule gives its own reason.
    #[test]
    fn media_the_old_host_and_the_same_device_come_first() {
        for p_h in [ANY, TOR, LAN] {
            for mine in [ANY, TOR, LAN] {
                let m = Mine::of(mine);
                assert_eq!(decide(p_h, m, false, true, false), Decision::NoMedia);
                assert_eq!(decide(p_h, m, false, false, true), Decision::NoMedia);
                let old = decide(p_h, m, true, false, true);
                let same = decide(p_h, m, true, true, true);
                if mine == LAN || p_h == LAN {
                    assert_eq!(old, Decision::LanRefused, "host {p_h:?}, viewer {mine:?}");
                    assert_eq!(same, Decision::LanRefused, "host {p_h:?}, viewer {mine:?}");
                } else {
                    assert_eq!(old, tor(None, TorWhy::OldHost));
                    assert_eq!(same, tor(Some(fallback::OFF), TorWhy::SameDevice));
                }
            }
        }
        let bridged = Mine {
            policy: TOR,
            bridged: true,
        };
        assert_eq!(
            decide(ANY, bridged, true, true, false),
            tor(Some(fallback::OFF), TorWhy::Bridge)
        );
        assert_eq!(
            decide(TOR, bridged, true, true, false),
            tor(Some(fallback::OFF), TorWhy::HostPolicy),
            "the host's policy is the reason when both are off"
        );
    }

    /// `Mine::from_knob`: the bridge rule turns `any` into `tor_only` with
    /// the `bridge` reason; a configured `tor_only` stays `here-off` while
    /// bridged; `direct_with_bridges` and `lan_only` are untouched by it.
    #[test]
    fn the_bridge_rule_gives_its_own_reason() {
        let knob = TransportKnob::new(&Network::default());
        assert_eq!(Mine::from_knob(&knob), Mine::of(ANY));
        knob.set_bridged(true);
        assert_eq!(
            Mine::from_knob(&knob),
            Mine {
                policy: TOR,
                bridged: true
            }
        );
        let paranoid = Network {
            paranoid: true,
            ..Network::default()
        };
        knob.set_from(&paranoid);
        assert_eq!(Mine::from_knob(&knob), Mine::of(TOR));
        let with_bridges = Network {
            direct_with_bridges: true,
            ..Network::default()
        };
        knob.set_from(&with_bridges);
        assert_eq!(Mine::from_knob(&knob), Mine::of(ANY));
        let lan_only = Network {
            lan_only: true,
            ..Network::default()
        };
        knob.set_from(&lan_only);
        assert_eq!(Mine::from_knob(&knob), Mine::of(LAN));
    }

    /// The CLI names and the codes of every reason (the direct design §3.1,
    /// §6.1), and how the host's own reasons are read.
    #[test]
    fn every_reason_has_its_name_and_code() {
        let table = [
            (TorWhy::HostPolicy, "policy", Some(fallback::PEER_OFF)),
            (TorWhy::HereOff, "here-off", Some(fallback::OFF)),
            (TorWhy::Bridge, "bridge", Some(fallback::OFF)),
            (TorWhy::OldHost, "old-host", None),
            (TorWhy::SameDevice, "same-device", Some(fallback::OFF)),
            (
                TorWhy::Fallback(FallbackWhy::HereNoAddresses),
                "here-no-addresses",
                Some(fallback::NO_ADDRESSES),
            ),
            (
                TorWhy::Fallback(FallbackWhy::HostNoAddresses),
                "host-no-addresses",
                Some(fallback::PEER_OFF),
            ),
            (
                TorWhy::Fallback(FallbackWhy::HereSocket),
                "here-socket",
                Some(fallback::SOCKET),
            ),
            (
                TorWhy::Fallback(FallbackWhy::HostSocket),
                "host-socket",
                Some(fallback::PEER_OFF),
            ),
            (
                TorWhy::Fallback(FallbackWhy::HostSilent),
                "host-silent",
                Some(fallback::PEER_SILENT),
            ),
            (
                TorWhy::Fallback(FallbackWhy::NoPath { heard: false }),
                "no-path",
                Some(fallback::NO_PATH),
            ),
            (
                TorWhy::Fallback(FallbackWhy::NoPath { heard: true }),
                "no-path-firewall",
                Some(fallback::NO_PATH),
            ),
            (
                TorWhy::Fallback(FallbackWhy::Quic),
                "quic",
                Some(fallback::QUIC),
            ),
        ];
        for (why, name, code) in table {
            assert_eq!(why.cli_name(), name);
            assert_eq!(why.code(), code, "{why:?}");
        }
        assert_eq!(
            TorWhy::from_host_reason(Some(fallback::OFF)),
            TorWhy::HostPolicy
        );
        assert_eq!(
            TorWhy::from_host_reason(Some(fallback::NO_ADDRESSES)),
            TorWhy::Fallback(FallbackWhy::HostNoAddresses)
        );
        assert_eq!(
            TorWhy::from_host_reason(Some(fallback::SOCKET)),
            TorWhy::Fallback(FallbackWhy::HostSocket)
        );
        for unknown in [
            None,
            Some(0),
            Some(fallback::NO_PATH),
            Some(9),
            Some(u32::MAX),
        ] {
            assert_eq!(
                TorWhy::from_host_reason(unknown),
                TorWhy::Fallback(FallbackWhy::NoPath { heard: false }),
                "{unknown:?}"
            );
        }
    }

    /// The `ROUTE` words of the direct design §3.5.
    #[test]
    fn the_route_words_are_the_clis() {
        let route = |same_site, ipv6| PathEnd::Direct(Route { same_site, ipv6 });
        assert_eq!(route(true, false).route_words(), "direct lan");
        assert_eq!(route(true, true).route_words(), "direct lan ipv6");
        assert_eq!(route(false, false).route_words(), "direct internet");
        assert_eq!(route(false, true).route_words(), "direct internet ipv6");
        assert_eq!(PathEnd::Tor(TorWhy::HostPolicy).route_words(), "tor policy");
        assert_eq!(
            PathEnd::Tor(TorWhy::Fallback(FallbackWhy::NoPath { heard: true })).route_words(),
            "tor no-path-firewall"
        );
        assert_eq!(PathEnd::NoMedia.route_words(), "none");
        assert_eq!(PathEnd::LanRefused.route_words(), "none no-lan-path");
    }
}
