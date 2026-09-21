//! The host role of `tornect host`: the handshake FSM wired to its real seams
//! (`docs/PLAN.md` §B.2, §B.8.14 M1), and the first-frame dispatch that keeps
//! the pairing-free `tornect ping` answering on the same port (decision M1-42).
//!
//! [`wire`] builds everything a stream is served with. The kill switch and the
//! live-session tracker are shared with the IPC context, so a `tornect panic`
//! (or `unattended off`) reaches every handshake and session this host serves,
//! and the guard refuses access-increasing changes while one is live.

use std::sync::Arc;

use anyhow::Context as _;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Instant;
use tornect_core::session_log::{SessionLog, SessionMode};
use tornect_core::unattended::limiter::{AttemptLimiter, HostTransport};
use tornect_core::unattended::schedule::FixedOffset;
use tornect_core::{Config, HostIdentity, Paths};
use tornect_signal::consent::TransportPolicy;
use tornect_signal::dispatch::{FIRST_FRAME_DEADLINE, FirstFrame, first_frame};
use tornect_signal::envelope::codes;
use tornect_signal::fsm::HostAudit;
use tornect_signal::fsm::host::{
    HostConfig, HostDeps, HostOutcome, KillSwitch, LiveSession, LiveSessions, SessionEnd,
    SessionSink, serve_host,
};
use tornect_signal::messages::{self, bye, pair_reject, reject};
use tornect_signal::pairing::{Consent, TrustedDeviceStore};
use tornect_signal::ping::{self, ServeLimits};
use tornect_signal::unattended::{EmergencyStop, GuardAdmin, UnattendedAuth};

use crate::unattended::HostContext;

/// Everything `tornect host` serves its signaling streams with.
pub struct HostWiring {
    /// Static facts sent in the handshake.
    pub cfg: HostConfig,
    /// The FSM's seams.
    pub deps: HostDeps,
    /// The IPC context, sharing `deps.kill` and [`Self::live`]. `None` when the
    /// unattended store could not be opened: then unattended requests are
    /// refused `NOT_GRANTED`, no stop code is honoured, and there is no control
    /// channel — attended pairing and sessions still work.
    pub ctx: Option<HostContext>,
    /// The sessions live right now.
    pub live: Arc<LiveSessions>,
    /// `sessions.log` as the FSM writes it (flushed at shutdown).
    pub audit: Arc<HostAudit>,
}

/// Wire the host FSM for `paths`: `consent` answers the popups, `identity`
/// signs, `device_pk` is the host's device key (its QUIC identity, §B.6).
pub fn wire(
    paths: &Paths,
    cfg: &Config,
    identity: Arc<HostIdentity>,
    device_pk: [u8; 32],
    consent: Arc<dyn Consent>,
) -> anyhow::Result<HostWiring> {
    let kill = KillSwitch::new();
    let live = Arc::new(LiveSessions::new());
    let ctx = match crate::unattended::host_context(paths, live.clone(), kill.clone()) {
        Ok(ctx) => Some(ctx),
        Err(e) => {
            eprintln!(
                "warning: unattended access and the control channel are unavailable ({e:#}); \
                 attended pairing and sessions still work"
            );
            None
        }
    };
    let trusted = Arc::new(
        TrustedDeviceStore::open(paths.trusted_devices_file())
            .context("opening the trusted-devices store")?,
    );
    // One handle on `sessions.log` for the whole host: the log is a hash chain
    // whose lock lives in the handle, and the grant store keys it. A second
    // handle writing concurrently could fork the chain.
    let log = ctx.as_ref().map_or_else(
        || SessionLog::new(paths.sessions_log()),
        |ctx| ctx.log.clone(),
    );
    let audit = Arc::new(HostAudit::new(Arc::new(log)));

    let mut deps = HostDeps::headless(identity, trusted);
    deps.consent = consent;
    deps.audit = audit.clone();
    deps.sessions = Arc::new(CliSessions {
        live: Arc::clone(&live),
    });
    deps.activity = live.clone();
    deps.kill = kill.clone();

    let mut host_cfg = HostConfig::new(cfg.general.device_name.clone(), device_pk);
    host_cfg.transport_policy =
        TransportPolicy::from_privacy(cfg.network.paranoid, cfg.network.lan_only);

    if let Some(ctx) = &ctx {
        deps.stop_token = Arc::new(EmergencyStop::new(Arc::clone(&ctx.guard), kill));
        // M1 has no local-zone source (decision M1-15; a tzdb-backed zone is
        // M6). The zone only matters for grant schedules, and no path in this
        // build creates one: the presets have none and `tornect unattended
        // grant` sends none.
        deps.unattended = Arc::new(
            UnattendedAuth::new(
                AttemptLimiter::new(ctx.guard.store().clone()),
                Arc::new(FixedOffset::utc()),
                HostTransport {
                    paranoid: cfg.network.paranoid,
                    lan_only: cfg.network.lan_only,
                },
            )
            .with_admin_authority(Arc::new(GuardAdmin::new(Arc::clone(&ctx.guard)))),
        );
        host_cfg.feats = vec![messages::feats::UA1.to_owned()];
    }

    Ok(HostWiring {
        cfg: host_cfg,
        deps,
        ctx,
        live,
        audit,
    })
}

/// The CLI's [`SessionSink`]: records each session in the tracker, and says on
/// the terminal when one starts and ends — the M1 stand-in for the §B.6
/// sharing indicator (nothing is captured yet).
struct CliSessions {
    live: Arc<LiveSessions>,
}

impl SessionSink for CliSessions {
    fn on_start(&self, session: &LiveSession<'_>) {
        self.live.on_start(session);
        println!("SESSION LIVE {}", session.session_id);
        eprintln!(
            "session with \"{}\" is live ({}{}); `tornect panic` ends it",
            session.label,
            mode_name(session.mode),
            if session.unattended {
                ", unattended"
            } else {
                ""
            },
        );
    }

    fn on_end(&self, session_id: &str, end: Option<&SessionEnd>) {
        self.live.on_end(session_id, end);
        println!("SESSION ENDED {session_id}");
        eprintln!(
            "session ended: {}",
            end.map_or_else(|| "protocol error".to_owned(), describe_end)
        );
    }
}

fn mode_name(mode: SessionMode) -> &'static str {
    match mode {
        SessionMode::ViewOnly => "view-only",
        _ => "control",
    }
}

fn describe_end(end: &SessionEnd) -> String {
    match end {
        SessionEnd::PeerBye(reason) => format!("the client left ({})", bye::name(*reason)),
        SessionEnd::PeerError(code) => {
            format!("the client reported an error ({})", codes::name(*code))
        }
        SessionEnd::PeerClosed => "the client closed the connection".to_owned(),
        SessionEnd::Killed(reason) => format!("ended here ({})", bye::name(*reason)),
        SessionEnd::Orphaned => "the client chose no transport in time".to_owned(),
        SessionEnd::Idle => "no traffic for the idle timeout".to_owned(),
        other => format!("{other:?}"),
    }
}

/// What one signaling stream amounted to (`tornect host --once` stops after
/// the first answered ping or finished session).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Served {
    /// The ping protocol answered this many pings.
    Pings(u32),
    /// A session was established and has ended.
    Session,
    /// A handshake that established no session.
    Handshake,
    /// No complete first frame.
    Nothing,
}

/// Serve one stream from the signaling port: route it by its first frame to the
/// ping protocol or to the FSM, and report the result on the terminal.
/// `answered` sees the running count after each pong.
pub async fn serve_signaling<S, F>(
    stream: S,
    cfg: &HostConfig,
    deps: &HostDeps,
    answered: F,
) -> Served
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    F: FnMut(u32),
{
    let started = Instant::now();
    match first_frame(stream, FIRST_FRAME_DEADLINE).await {
        FirstFrame::Ping(mut stream) => {
            eprintln!("ping client connected over Tor");
            // The session budget counts from the first byte, as it did when the
            // ping protocol read that frame itself.
            let limits = ServeLimits {
                session_deadline: ping::SESSION_TIMEOUT.saturating_sub(started.elapsed()),
                ..ServeLimits::default()
            };
            let mut count = 0;
            let mut answered = answered;
            let outcome = ping::serve_with_limits(&mut stream, limits, |n| {
                count = n;
                answered(n);
            })
            .await;
            match outcome {
                Ok(n) => eprintln!("ping client disconnected after {n} ping(s)"),
                Err(e) => eprintln!("ping session ended: {e}"),
            }
            Served::Pings(count)
        }
        FirstFrame::Handshake(stream) => match serve_host(stream, cfg, deps).await {
            Ok(outcome) => {
                if let Some(line) = describe_outcome(&outcome) {
                    eprintln!("{line}");
                }
                if matches!(outcome, HostOutcome::Session { .. }) {
                    Served::Session
                } else {
                    Served::Handshake
                }
            }
            Err(e) => {
                eprintln!("handshake ended: {e}");
                Served::Handshake
            }
        },
        FirstFrame::Gone(why) => {
            tracing::debug!(?why, "signaling stream closed before its first frame");
            Served::Nothing
        }
    }
}

/// One line for a handshake that ended without a live session (the sink
/// already reported the ones that had one).
fn describe_outcome(outcome: &HostOutcome) -> Option<String> {
    Some(match outcome {
        HostOutcome::PairRejected { device, reason } => format!(
            "pairing refused for device {} ({})",
            device.fingerprint(),
            pair_reject::name(*reason)
        ),
        HostOutcome::PairedOnly { label, .. } => {
            format!("paired with \"{label}\"; it left without asking for a session")
        }
        HostOutcome::SessionRejected { label, reason, .. } => {
            format!(
                "session refused for \"{label}\" ({})",
                reject::name(*reason)
            )
        }
        HostOutcome::Admin { device, ok } => format!(
            "remote admin command from device {} {}",
            device.fingerprint(),
            if *ok { "executed" } else { "refused" }
        ),
        HostOutcome::Session { .. } => return None,
        _ => "handshake finished".to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::duplex;
    use tornect_core::DeviceIdentity;
    use tornect_core::unattended::guard::RemoteSessionActivity;
    use tornect_core::unattended::ipc::{IpcOp, IpcRequest, codes as codes_ipc};
    use tornect_signal::HostSigner;
    use tornect_signal::fsm::client::{
        ClientConfig, ClientDeps, ClientOutcome, Intent, ScriptedClientUi, connect,
    };
    use tornect_signal::pairing::{
        KnownHostStore, PairDecision, PairScript, ScriptedConsent, SessionDecision, SessionScript,
    };

    use super::*;

    struct Env {
        _tmp: tempfile::TempDir,
        paths: Paths,
        identity: Arc<HostIdentity>,
    }

    fn env() -> Env {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        paths.ensure().unwrap();
        Env {
            _tmp: tmp,
            paths,
            identity: Arc::new(HostIdentity::from_seed(&[0x11; 32])),
        }
    }

    fn client(env: &Env) -> (DeviceIdentity, ClientConfig, ClientDeps) {
        let known = Arc::new(
            KnownHostStore::open(env.paths.state_dir.join("client-known-hosts.toml")).unwrap(),
        );
        let mut deps = ClientDeps::headless(known);
        deps.ui = Arc::new(ScriptedClientUi::new(true));
        (
            DeviceIdentity::from_seed(&[0x22; 32]),
            ClientConfig::new(env.identity.id(), "Laptop"),
            deps,
        )
    }

    /// The FSM audits into the host's `sessions.log`, and a host whose store
    /// opened offers the unattended suite.
    #[test]
    fn the_fsm_audits_into_the_hosts_log() {
        let env = env();
        let wiring = wire(
            &env.paths,
            &Config::default(),
            Arc::clone(&env.identity),
            [9; 32],
            Arc::new(ScriptedConsent::new()),
        )
        .unwrap();
        let ctx = wiring
            .ctx
            .as_ref()
            .expect("the store opens in a fresh home");
        assert_eq!(wiring.audit.log().path(), ctx.log.path());
        assert!(wiring.deps.kill.fired().is_none());
        assert_eq!(
            wiring.cfg.feats,
            vec![messages::feats::UA1.to_owned()],
            "a host with a store offers the unattended suite"
        );
    }

    /// The whole reason for the wiring. `tornect panic` (IPC `Panic`) ends a
    /// live session: before, the IPC context had no kill switch, so `Panic`
    /// answered `G_PRECONDITION` and the session ran on. And the guard sees the
    /// session: `unattended on` is refused while it runs and for the cool-down
    /// after (§B.8.6.2), where before the guard was told no session ever runs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ipc_panic_ends_a_live_session() {
        let env = env();
        let consent = Arc::new(ScriptedConsent::new());
        consent.push_pairing(PairScript::Decide(PairDecision::Accept { label: None }));
        consent.push_session(SessionScript::Decide(SessionDecision::AllowOnce));
        let wiring = wire(
            &env.paths,
            &Config::default(),
            Arc::clone(&env.identity),
            HostSigner::public_key(&DeviceIdentity::from_seed(&[0x33; 32])),
            consent,
        )
        .unwrap();
        let ctx = wiring.ctx.as_ref().unwrap();

        let (client_end, host_end) = duplex(64 * 1024);
        let (cfg, deps) = (wiring.cfg.clone(), wiring.deps.clone());
        let host_task =
            tokio::spawn(async move { serve_signaling(host_end, &cfg, &deps, |_| {}).await });
        let (identity, ccfg, cdeps) = client(&env);
        let mut session = match connect(client_end, &ccfg, &identity, &cdeps, Intent::Session)
            .await
            .unwrap()
        {
            ClientOutcome::Session(s) => s,
            other => panic!("expected a session, got {other:?}"),
        };
        session.send_tor_fallback().await.unwrap();
        session.ping().await.unwrap();
        assert_eq!(wiring.live.count(), 1);
        assert!(
            RemoteSessionActivity::session_live(&*wiring.live),
            "the guard's activity source sees the session"
        );
        // Refused before any re-auth dialog could open.
        let on = |id| crate::unattended::dispatch(ctx, IpcRequest { id, op: IpcOp::On });
        let refused = on(2);
        assert!(!refused.ok);
        assert_eq!(
            refused.code,
            codes_ipc::G_REMOTE_SESSION_ACTIVE,
            "{refused:?}"
        );

        let resp = crate::unattended::dispatch(
            ctx,
            IpcRequest {
                id: 1,
                op: IpcOp::Panic,
            },
        );
        assert!(resp.ok, "{resp:?}");

        let event = session.next_event(Duration::from_secs(10)).await.unwrap();
        assert_eq!(
            event,
            Some(tornect_signal::fsm::client::SessionEvent::Bye {
                reason: bye::PANIC,
                detail: None
            })
        );
        assert_eq!(host_task.await.unwrap(), Served::Session);
        assert_eq!(wiring.live.count(), 0);
        assert!(wiring.live.last_session_ended_at().is_some());
        // Still refused: the cool-down runs from the session's end.
        assert_eq!(on(3).code, codes_ipc::G_REMOTE_SESSION_ACTIVE);
    }

    /// Both protocols answer on the one port: a ping stream is served by the
    /// ping protocol, with no pairing and no popup.
    #[tokio::test]
    async fn a_ping_needs_no_pairing() {
        let env = env();
        let consent = Arc::new(ScriptedConsent::new());
        let wiring = wire(
            &env.paths,
            &Config::default(),
            Arc::clone(&env.identity),
            [9; 32],
            consent.clone(),
        )
        .unwrap();
        let (mut client_end, host_end) = duplex(1024);
        let (cfg, deps) = (wiring.cfg.clone(), wiring.deps.clone());
        let host_task =
            tokio::spawn(async move { serve_signaling(host_end, &cfg, &deps, |_| {}).await });
        for i in 0..2u8 {
            ping::ping(&mut client_end, [i; ping::NONCE_LEN])
                .await
                .unwrap();
        }
        drop(client_end);
        assert_eq!(host_task.await.unwrap(), Served::Pings(2));
        assert!(consent.sas_shown().is_empty(), "no popup for a ping");
        assert_eq!(wiring.live.count(), 0);
    }
}
