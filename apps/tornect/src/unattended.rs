//! The host-role IPC dispatch loop and the `tornect unattended` CLI
//! (`docs/PLAN.md` §B.8.7.4).
//!
//! Three things live here, and the split matters:
//!
//! 1. [`dispatch`] turns one [`IpcOp`] into one [`IpcResponse`] by calling the
//!    [`MutationGuard`]. It is pure logic over a context — no socket, no clap.
//! 2. [`serve`] runs it behind the `tornect-platform` endpoint for the host role.
//! 3. [`run_unattended`] is the CLI, which reaches [`dispatch`] by **one of two
//!    routes**:
//!    over the socket when a host is running, or directly when none is.
//!
//! That the two routes share [`dispatch`] is the point, not an implementation
//! detail. §B.8.7.4 says the offline CLI "runs the guard offline like any other
//! mutation" — if the two paths were written separately, one would eventually
//! forget a re-auth or a log line, and only on the path nobody tests.

use std::sync::Arc;

use anyhow::Context as _;
use clap::Subcommand;
use tornect_core::id::DeviceId;
use tornect_core::session_log::{Actor, SessionLog};
use tornect_core::unattended::grant::Preset;
use tornect_core::unattended::guard::{
    ExternalOp, GuardError, MutationGuard, RemoteSessionActivity, SuspendOutcome,
};
use tornect_core::unattended::ipc::{
    GrantOptions, IpcOp, IpcRequest, IpcResponse, LogPage, MasterOnPayload, PolicyInputsPayload,
    RegStartPayload, codes, encode_payload,
};
use tornect_core::unattended::readiness::ReadinessSnapshot;
use tornect_core::unattended::store::{GrantStore, LoadMode};
use tornect_core::{Config, Paths};
use tornect_platform::ipc::{Endpoint, Reply};
use tornect_signal::fsm::host::KillSwitch;

/// Everything the dispatch needs, whichever route reached it.
pub struct HostContext {
    /// The single enforcement point of §B.8.6.2.
    pub guard: Arc<MutationGuard>,
    /// This host's onion identity key, for `master_on`'s stop token.
    pub host_onion_pk: [u8; 32],
    /// M1: the all-unknown stub (§B.8.14); M6 fills it from the platform probes.
    pub readiness: ReadinessSnapshot,
    /// `zxcvbn` inputs for `PolicyInputs` (§B.8.7.2).
    pub user_inputs: Vec<String>,
    /// Ends live handshakes. `None` on the offline route — there are none.
    pub kill: Option<KillSwitch>,
    /// `sessions.log`, for `Log`.
    pub log: SessionLog,
}

impl HostContext {
    /// The §B.8.7.2 minimum `zxcvbn` score: 4 on a file-keystore host, 3 otherwise.
    #[must_use]
    pub fn min_score(&self) -> u8 {
        use tornect_core::keystore::KeystoreKind;
        if self.guard.store().keystore_kind() == KeystoreKind::File {
            4
        } else {
            3
        }
    }
}

/// Map a guard failure to the `G_*` / `E_*` code and detail of §B.8.7.4.
fn guard_fail(id: u64, e: &GuardError) -> IpcResponse {
    IpcResponse::fail(id, e.code(), e.to_string())
}

/// Answer one request. Never panics: every arm returns a response, because a
/// dispatch that dies takes the host's whole control channel with it.
pub fn dispatch(ctx: &HostContext, req: IpcRequest) -> IpcResponse {
    let id = req.id;
    let by = Actor::Cli;
    let guard = &ctx.guard;

    macro_rules! unit {
        ($e:expr) => {
            match $e {
                Ok(_) => IpcResponse::ok(id),
                Err(ref e) => guard_fail(id, e),
            }
        };
    }

    match req.op {
        IpcOp::Status => {
            let report = guard.store().status_report(ctx.readiness.clone());
            match encode_payload(&report) {
                Ok(p) => IpcResponse::ok_with(id, p),
                Err(e) => IpcResponse::fail(id, e.code(), e.to_string()),
            }
        }

        IpcOp::On => match guard.master_on(by, &ctx.host_onion_pk) {
            Ok(ok) => {
                // The emergency stop card (§B.8.7.4) is shown once and never
                // stored. It travels in the payload rather than in `detail`
                // because `detail` is a human-readable string that ends up in
                // logs and error messages; a 16-byte secret must not.
                let payload = MasterOnPayload {
                    stop_code: *ok.stop_code,
                };
                match encode_payload(&payload) {
                    Ok(p) => IpcResponse::ok_with(id, p),
                    Err(e) => IpcResponse::fail(id, e.code(), e.to_string()),
                }
            }
            Err(ref e) => guard_fail(id, e),
        },

        IpcOp::Off => {
            let r = unit!(guard.master_off(by));
            if r.ok
                && let Some(k) = &ctx.kill
            {
                k.kill(tornect_signal::messages::bye::MASTER_OFF);
            }
            r
        }
        IpcOp::Pause { until } => {
            let r = unit!(guard.pause(by, until));
            if r.ok
                && let Some(k) = &ctx.kill
            {
                k.kill(tornect_signal::messages::bye::PAUSED);
            }
            r
        }
        IpcOp::Revoke { device } => unit!(guard.revoke(by, &device)),
        IpcOp::RevokeAll => {
            let r = unit!(guard.revoke_all(by));
            if r.ok
                && let Some(k) = &ctx.kill
            {
                k.kill(tornect_signal::messages::bye::REVOKED);
            }
            r
        }
        IpcOp::Unlock { device } => unit!(guard.unlock(by, &device)),
        IpcOp::Suspend { device } => match guard.suspend(by, &device) {
            // A no-op is still a success: §B.8.6.3 says a local Block or panic
            // outranks this, and the caller asked for "suspended", which it is.
            Ok(SuspendOutcome::Suspended) => IpcResponse::ok(id),
            Ok(SuspendOutcome::NoOp) => {
                let mut r = IpcResponse::ok(id);
                r.detail = Some("already suspended locally; unchanged".to_owned());
                r
            }
            Err(ref e) => guard_fail(id, e),
        },
        IpcOp::Resume { device } => unit!(guard.resume(by, &device)),
        IpcOp::Enable { device } => unit!(guard.enable(by, &device)),
        IpcOp::Disable { device } => unit!(guard.disable(by, &device)),

        IpcOp::ServiceInstall { elevated } => {
            // The guard performs the re-auth and the log line; the *effect* —
            // writing a systemd user unit / Task Scheduler entry / LaunchAgent —
            // is `tornect-platform` work scheduled at M6 (§B.8.14 "autostart
            // installers"). Authorising and then reporting honestly beats
            // returning `ok` for something that did not happen.
            match guard.authorize(by, &ExternalOp::ServiceInstall { elevated }) {
                Ok(()) => IpcResponse::fail(
                    id,
                    codes::G_PRECONDITION,
                    "autostart installation lands at M6 (docs/PLAN.md §B.8.14); \
                     the change was authorised and logged but not applied",
                ),
                Err(ref e) => guard_fail(id, e),
            }
        }
        IpcOp::ServiceUninstall => match guard.authorize(by, &ExternalOp::ServiceUninstall) {
            Ok(()) => IpcResponse::fail(
                id,
                codes::G_PRECONDITION,
                "autostart removal lands at M6 (docs/PLAN.md §B.8.14); \
                 the change was authorised and logged but not applied",
            ),
            Err(ref e) => guard_fail(id, e),
        },

        IpcOp::Readiness => match encode_payload(&ctx.readiness) {
            Ok(p) => IpcResponse::ok_with(id, p),
            Err(e) => IpcResponse::fail(id, e.code(), e.to_string()),
        },

        // `read_all_including_rotated`, not `read_all`: someone asking for the
        // log wants the history, and a 10 MiB rotation has already moved older
        // sessions out of the live file.
        IpcOp::Log { filter, after } => match ctx.log.read_all_including_rotated() {
            Ok(records) => {
                let lines: Vec<String> = records
                    .iter()
                    .filter_map(|r| serde_json::to_string(r).ok())
                    .collect();
                let page = LogPage::page(&lines, &filter, after);
                match encode_payload(&page) {
                    Ok(p) => IpcResponse::ok_with(id, p),
                    Err(e) => IpcResponse::fail(id, e.code(), e.to_string()),
                }
            }
            Err(e) => IpcResponse::fail(id, codes::G_PRECONDITION, e.to_string()),
        },

        IpcOp::Panic => {
            // §B.8.7.4: the panic key "ends any session and, if it was
            // unattended, suspends that grant". Ending sessions is what the
            // kill switch does: `tornect host` arms every stream with this
            // switch, so this ends every handshake and session it serves.
            // Suspending the grant behind an unattended session is the M4 half
            // (`tornect-session` owns live sessions); M1 ends what it can reach
            // and says so rather than suspending an arbitrary grant.
            match &ctx.kill {
                Some(k) => {
                    k.kill(tornect_signal::messages::bye::PANIC);
                    let mut r = IpcResponse::ok(id);
                    r.detail = Some(
                        "every handshake and session was ended; suspending the grant behind \
                         an unattended session lands at M4 (docs/PLAN.md §B.8.14)"
                            .to_owned(),
                    );
                    r
                }
                None => IpcResponse::fail(
                    id,
                    codes::G_PRECONDITION,
                    "no host is running here, so there is no session to end",
                ),
            }
        }

        IpcOp::BackupExport { path } => {
            match guard.authorize(by, &ExternalOp::BackupExport { path: path.clone() }) {
                Ok(()) => IpcResponse::fail(
                    id,
                    codes::G_PRECONDITION,
                    "backup export lands at M8 (docs/PLAN.md §B.8.14); \
                     the request was authorised and logged but nothing was written",
                ),
                Err(ref e) => guard_fail(id, e),
            }
        }
        IpcOp::BackupImport { path } => {
            match guard.authorize(by, &ExternalOp::BackupImport { path: path.clone() }) {
                Ok(()) => IpcResponse::fail(
                    id,
                    codes::G_PRECONDITION,
                    "backup import lands at M8 (docs/PLAN.md §B.8.14); \
                     the request was authorised and logged but nothing was read",
                ),
                Err(ref e) => guard_fail(id, e),
            }
        }

        IpcOp::PolicyInputs => {
            let payload = PolicyInputsPayload {
                user_inputs: ctx.user_inputs.clone(),
                min_score: ctx.min_score(),
            };
            match encode_payload(&payload) {
                Ok(p) => IpcResponse::ok_with(id, p),
                Err(e) => IpcResponse::fail(id, e.code(), e.to_string()),
            }
        }

        IpcOp::RegStart {
            device,
            reg_request,
        } => match guard.reg_start(by, &device) {
            Ok(ok) => {
                let setup = match tornect_signal::auth::parse_server_setup(&ok.server_setup) {
                    Ok(s) => s,
                    Err(e) => {
                        return IpcResponse::fail(id, codes::G_PRECONDITION, e.to_string());
                    }
                };
                // `credential_identifier` is the device public key, the same
                // value the login uses (§B.8.4.3).
                match tornect_signal::auth::registration_response(
                    &setup,
                    &reg_request,
                    device.public_key_bytes(),
                ) {
                    Ok(reg_response) => {
                        let payload = RegStartPayload {
                            reg_response,
                            reg_txn: *ok.reg_txn,
                        };
                        match encode_payload(&payload) {
                            Ok(p) => IpcResponse::ok_with(id, p),
                            Err(e) => IpcResponse::fail(id, e.code(), e.to_string()),
                        }
                    }
                    Err(e) => IpcResponse::fail(id, codes::G_PRECONDITION, e.to_string()),
                }
            }
            Err(ref e) => guard_fail(id, e),
        },

        IpcOp::RegFinish {
            device,
            reg_txn,
            upload,
            preset,
            options,
        } => {
            let Some(preset) = Preset::from_wire(preset) else {
                return IpcResponse::fail(id, codes::E_BAD_LEN, "unknown preset");
            };
            unit!(guard.reg_finish(by, &device, &reg_txn, &upload, preset, &options))
        }

        IpcOp::Unknown(tag) => {
            IpcResponse::fail(id, codes::E_UNKNOWN_KIND, format!("unknown op tag {tag}"))
        }
    }
}

/// [`dispatch`], plus what to undo if the answer never reaches the CLI.
///
/// Only `On` needs an undo. Its answer carries the one-time emergency stop code
/// (§B.8.7.4), which exists nowhere else; if the CLI was killed or hung up while
/// the re-authentication dialog was open, access would otherwise stay on under
/// a stop card nobody holds (track D S1). Every other op's effect is what the
/// owner asked for and answered the dialog for, seen or not.
fn reply(ctx: &Arc<HostContext>, req: IpcRequest) -> Reply {
    let is_on = matches!(req.op, IpcOp::On);
    let response = dispatch(ctx, req);
    let on_undelivered: Option<Box<dyn FnOnce() + Send>> = if is_on && response.ok {
        let ctx = Arc::clone(ctx);
        Some(Box::new(move || {
            match ctx.guard.master_off_undelivered_stop_code(Actor::Cli) {
                Ok(()) => tracing::warn!(
                    "the new emergency stop code never reached the CLI; unattended access \
                     was turned back off"
                ),
                Err(e) => tracing::error!(
                    error = %e,
                    "the new emergency stop code never reached the CLI, and turning \
                     unattended access back off FAILED"
                ),
            }
            if let Some(k) = &ctx.kill {
                k.kill(tornect_signal::messages::bye::MASTER_OFF);
            }
        }))
    } else {
        None
    };
    Reply {
        response,
        on_undelivered,
    }
}

/// Serve the host role's control channel on `endpoint` until the task is
/// dropped.
pub async fn serve(ctx: Arc<HostContext>, endpoint: &Endpoint) -> anyhow::Result<()> {
    tracing::info!(path = %endpoint.path().display(), "IPC endpoint listening");
    endpoint
        .serve(move |req| {
            let ctx = Arc::clone(&ctx);
            async move {
                // Guard calls are blocking (fsync, and the re-auth dialog):
                // off the reactor they go.
                tokio::task::spawn_blocking(move || reply(&ctx, req))
                    .await
                    .unwrap_or_else(|e| {
                        IpcResponse::fail(
                            0,
                            codes::G_PRECONDITION,
                            format!("dispatch panicked: {e}"),
                        )
                        .into()
                    })
            }
        })
        .await
        .context("serving IPC")
}

/// [`serve`] for a host whose unattended store did not open (`why`): `tornect
/// panic` still ends every session, through `kill`, and every other request is
/// refused with the reason (SLICE-B2 B2-2).
pub async fn serve_without_store(
    kill: KillSwitch,
    why: String,
    endpoint: &Endpoint,
) -> anyhow::Result<()> {
    tracing::info!(path = %endpoint.path().display(), "IPC endpoint listening (panic only)");
    let why: Arc<str> = why.into();
    endpoint
        .serve(move |req| {
            let (kill, why) = (kill.clone(), Arc::clone(&why));
            async move { dispatch_without_store(&kill, &why, req) }
        })
        .await
        .context("serving IPC")
}

/// [`dispatch`] for a host with no store. Such a host serves no unattended
/// session, so there is no grant to suspend behind one.
fn dispatch_without_store(kill: &KillSwitch, why: &str, req: IpcRequest) -> IpcResponse {
    match req.op {
        IpcOp::Panic => {
            kill.kill(tornect_signal::messages::bye::PANIC);
            let mut r = IpcResponse::ok(req.id);
            r.detail = Some("every handshake and session was ended".to_owned());
            r
        }
        _ => IpcResponse::fail(
            req.id,
            codes::G_PRECONDITION,
            format!(
                "this host started without its unattended store ({why}), so it answers only \
                 `tornect panic`; stop it (Ctrl-C in its terminal) and start it again to use \
                 this command"
            ),
        ),
    }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// `tornect unattended …` (§B.8.7.4).
#[derive(Subcommand, Debug)]
pub enum UnattendedCmd {
    /// Show the master switch, every grant and its state, and readiness.
    Status {
        /// Print machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Turn unattended access on host-wide and print a new emergency stop code.
    On,
    /// Turn unattended access off host-wide. Live sessions end.
    Off,
    /// Pause unattended access for a while.
    Pause {
        /// How long, in seconds.
        #[arg(long, default_value_t = 3600)]
        secs: u64,
    },
    /// Give a paired device unattended access, setting its password.
    Grant {
        /// Device ID, fingerprint or pinned label.
        device: String,
        /// Which preset to apply.
        #[arg(long, value_enum, default_value_t = PresetArg::MyMachines)]
        preset: PresetArg,
        /// Waive the "prior attended session" precondition (warned and logged).
        #[arg(long)]
        waive_attended_check: bool,
    },
    /// Change a grant's password.
    SetPassword {
        /// Device ID, fingerprint or pinned label.
        device: String,
    },
    /// Re-enable a disabled grant.
    Enable {
        /// Device ID, fingerprint or pinned label.
        device: String,
    },
    /// Disable a grant without removing it.
    Disable {
        /// Device ID, fingerprint or pinned label.
        device: String,
    },
    /// Remove a grant.
    Revoke {
        /// Device ID, fingerprint or pinned label.
        device: Option<String>,
        /// Revoke every grant.
        #[arg(long, conflicts_with = "device")]
        all: bool,
    },
    /// Clear a grant's failure counters and lock.
    Unlock {
        /// Device ID, fingerprint or pinned label.
        device: String,
    },
    /// Suspend a grant (deny-direction; no re-authentication).
    Suspend {
        /// Device ID, fingerprint or pinned label.
        device: String,
    },
    /// Clear a suspension.
    Resume {
        /// Device ID, fingerprint or pinned label.
        device: String,
    },
    /// Print the readiness report.
    Readiness,
    /// Print `sessions.log`.
    Log {
        /// Only lines containing this substring.
        #[arg(long, default_value = "")]
        filter: String,
        /// Continue from a previous page's cursor.
        #[arg(long)]
        after: Option<u64>,
    },
}

/// `--preset`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum PresetArg {
    /// Own devices: Control, 3 s block window, 90 d auto-renewed.
    MyMachines,
    /// Headless media or gaming box: Control, no block window, keep-awake on.
    HeadlessBox,
    /// Helping a relative: view-only, 7 d, ask before starting.
    HelpingSomeone,
}

impl From<PresetArg> for Preset {
    fn from(p: PresetArg) -> Self {
        match p {
            PresetArg::MyMachines => Self::MyMachines,
            PresetArg::HeadlessBox => Self::HeadlessBox,
            PresetArg::HelpingSomeone => Self::HelpingSomeone,
        }
    }
}

/// `tornect service …` (§B.8.7.5).
#[derive(Subcommand, Debug)]
pub enum ServiceCmd {
    /// Register Tornect to start at login.
    Install {
        /// Windows only: an elevated task (§B.8.7.5 — opt-in, admin sessions).
        #[arg(long)]
        elevated: bool,
    },
    /// Remove the autostart registration.
    Uninstall,
    /// Report whether autostart is registered.
    Status,
}

/// `tornect backup …` (§B.8.7.4).
#[derive(Subcommand, Debug)]
pub enum BackupCmd {
    /// Write an encrypted backup of the unattended store.
    Export {
        /// Destination file.
        path: String,
    },
    /// Read a backup back (imported grants arrive disabled, §B.8.9).
    Import {
        /// Source file.
        path: String,
    },
}

/// How a CLI command reaches [`dispatch`].
///
/// §B.8.7.4: "with no host running the CLI runs the guard offline like any
/// other mutation". A running host holds the host lock for its whole life, so
/// the offline route is taken only when there is genuinely no host — not merely
/// none that answers (SLICE-B2 B2-2) — and the store's advisory lock keeps the
/// two from writing the store at once. The route is picked once, when the
/// command starts: a host that starts later is seen only by the offline
/// guard's session checks, which count its lock as a live session (SLICE-D D1).
enum Route {
    /// A host is listening; send the request to it.
    Host,
    /// No host; build the guard here and dispatch in-process.
    Offline(Box<HostContext>),
}

fn wall_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// The `ReAuth` backend this build and host should use, most-preferred first.
///
/// Ordering is deliberate: the debug escape wins **only** when it is armed,
/// which `DevReAuth::armed()` gates on `cfg(debug_assertions)`, so a release
/// binary can never take it however the environment is set.
fn reauth_backend() -> Arc<dyn tornect_core::unattended::guard::ReAuth> {
    use tornect_platform::reauth::DevReAuth;
    if DevReAuth::armed() {
        eprintln!(
            "warning: TORNECT_DEV_REAUTH=allow — OS re-authentication is WAIVED in this debug build"
        );
        return Arc::new(DevReAuth::new());
    }
    #[cfg(target_os = "linux")]
    {
        Arc::new(tornect_platform::reauth::PolkitReAuth::new())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Arc::new(tornect_platform::reauth::RefuseReAuth)
    }
}

/// The context a running `tornect host` serves its control channel with.
///
/// The same guard and the same [`dispatch`] as the offline route, deliberately.
/// Three things differ:
/// - The store's load (§B.8.5.1): the host's load settles pending charges,
///   applies decay and re-arms locks, which only the host may do.
/// - `kill` is the switch the host FSM arms every stream with, so `Panic`,
///   `Off`, `Pause` and `RevokeAll` end live sessions.
/// - The guard sees `activity`, the host's live-session tracker, so it refuses
///   access-increasing changes while a remote session is live (§B.8.6.2).
pub fn host_context(
    paths: &Paths,
    activity: Arc<dyn RemoteSessionActivity>,
    kill: KillSwitch,
) -> anyhow::Result<HostContext> {
    context(paths, LoadMode::Host, activity, Some(kill))
}

/// The offline CLI's context (no host running).
///
/// §B.8.5.1: "the offline CLI never applies or persists decay — the only
/// FailState write it performs is the reset of a local Unlock", and a *load*
/// is a host start or a keystore recovery, which a pre-authentication attacker
/// cannot force. Loading as the host here made every `tornect unattended
/// status` a load that settled, decayed and rewrote the store (track D S5).
fn offline_context(paths: &Paths) -> anyhow::Result<HostContext> {
    context(paths, LoadMode::Offline, offline_activity(paths), None)
}

/// What the offline guard asks about remote sessions: the host lock.
fn offline_activity(paths: &Paths) -> Arc<dyn RemoteSessionActivity> {
    Arc::new(HostLockActivity {
        paths: paths.clone(),
    })
}

/// The offline route's view of remote sessions (SLICE-D D1).
///
/// The route is picked once, when the command starts, but the command can wait
/// for minutes at a password prompt or in the re-auth dialog, and a
/// `tornect host` started meanwhile runs store-less beside it (M1-46). That
/// host's sessions are invisible here, so while any host holds the host lock
/// a session counts as live: the guard's checks before and after re-auth, and
/// last thing before the write, then refuse with `G_REMOTE_SESSION_ACTIVE`.
struct HostLockActivity {
    paths: Paths,
}

impl RemoteSessionActivity for HostLockActivity {
    fn last_session_ended_at(&self) -> Option<std::time::Instant> {
        None
    }

    fn session_live(&self) -> bool {
        crate::host::HostLock::holder(&self.paths).is_some()
    }
}

/// Build a context: the guard, told about live sessions by `activity`, and the
/// kill switch that ends them (`None` on the offline route, which has none).
///
/// Note the side effect: this creates the host identity if none exists, because
/// `master_on` needs the onion key to compute the stop token. `tornect id` does
/// the same and says so; here it happens on the first `tornect unattended`
/// command of any kind, including a read-only one.
fn context(
    paths: &Paths,
    mode: LoadMode,
    activity: Arc<dyn RemoteSessionActivity>,
    kill: Option<KillSwitch>,
) -> anyhow::Result<HostContext> {
    use tornect_core::keystore::{FileSecretStore, load_or_create_host_identity};
    use tornect_core::unattended::clock::SystemClock;
    use tornect_core::unattended::guard::{FilePairedDevices, SessionLogHistory};

    paths.ensure()?;
    let secrets = Arc::new(FileSecretStore::open(paths.keys_dir())?);
    let (host, _) = load_or_create_host_identity(&*secrets)?;
    let log = SessionLog::new(paths.sessions_log());
    let secrets_dyn = Arc::clone(&secrets) as Arc<dyn tornect_core::SecretStore>;
    let clock = Arc::new(SystemClock::default());
    let store = match mode {
        LoadMode::Host => GrantStore::open(paths, secrets_dyn, clock, log.clone())?,
        LoadMode::Offline => GrantStore::open_offline(paths, secrets_dyn, clock, log.clone())?,
    };
    let guard = MutationGuard::new(store, reauth_backend(), activity)
        .with_paired_devices(Arc::new(FilePairedDevices::new(
            paths.trusted_devices_file(),
        )))
        .with_attended_history(Arc::new(SessionLogHistory::new(log.clone())))
        .with_server_setup_source(Arc::new(
            tornect_signal::unattended::OpaqueServerSetupSource,
        ));
    let user_inputs = policy_user_inputs(paths, &host.id().onion_address(), &guard);
    Ok(HostContext {
        guard: Arc::new(guard),
        host_onion_pk: *host.id().public_key_bytes(),
        readiness: ReadinessSnapshot::unknown(),
        user_inputs,
        kill,
        log,
    })
}

/// The §B.8.7.2 `zxcvbn` inputs — {host name, device labels, onion address, OS
/// user name, "tornect"} — the things an attacker would guess first.
///
/// The labels are every paired device's and every grant's: a password built
/// around "Laptop-of-Ana" must score as the guessable thing it is (track D S9).
/// Every source is best-effort; a missing one only means fewer inputs.
fn policy_user_inputs(paths: &Paths, onion: &str, guard: &MutationGuard) -> Vec<String> {
    let mut inputs = vec!["tornect".to_owned(), onion.to_owned()];
    if let Ok(cfg) = Config::load(&paths.config_file()) {
        inputs.push(cfg.general.device_name);
    }
    if let Some(host) = os_host_name() {
        inputs.push(host);
    }
    if let Ok(user) = std::env::var("USER").or_else(|_| std::env::var("USERNAME")) {
        inputs.push(user);
    }
    if let Ok(trusted) =
        tornect_signal::pairing::TrustedDeviceStore::open(paths.trusted_devices_file())
    {
        inputs.extend(trusted.snapshot().devices.into_iter().map(|d| d.label));
    }
    inputs.extend(guard.store().grants().into_iter().map(|g| g.label));
    inputs.sort();
    inputs.dedup();
    inputs
}

/// The machine's host name, if the OS will say.
fn os_host_name() -> Option<String> {
    #[cfg(target_os = "linux")]
    let name = std::fs::read_to_string("/proc/sys/kernel/hostname").ok();
    #[cfg(not(target_os = "linux"))]
    let name = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok();
    name.map(|n| n.trim().to_owned()).filter(|n| !n.is_empty())
}

/// What serves this state directory.
enum Probe {
    /// A host that answers on its control channel.
    Host,
    /// A host holds the host lock but nothing answers: Windows until M6, or a
    /// failed bind. The holder, for messages.
    Unreachable(String),
    /// No host.
    NoHost,
}

async fn probe(paths: &Paths) -> Probe {
    if tornect_platform::ipc::is_running(&paths.state_dir).await {
        Probe::Host
    } else if let Some(holder) = crate::host::HostLock::holder(paths) {
        Probe::Unreachable(holder)
    } else {
        Probe::NoHost
    }
}

/// Pick the route: talk to a running host, or run the guard here — but never
/// beside a host that does not answer. The offline guard cannot see that
/// host's live sessions, so it would widen access under one (SLICE-B2 B2-2).
async fn route(paths: &Paths) -> anyhow::Result<Route> {
    match probe(paths).await {
        Probe::Host => Ok(Route::Host),
        Probe::Unreachable(holder) => anyhow::bail!(
            "{}; stop it (Ctrl-C in its terminal) and run this again",
            unreachable_host(paths, &holder)
        ),
        Probe::NoHost => Ok(Route::Offline(Box::new(offline_context(paths)?))),
    }
}

/// "A host runs here, but nothing answers for it."
fn unreachable_host(paths: &Paths, holder: &str) -> String {
    format!(
        "a Tornect host is running for {} ({holder}), but it has no control channel{}",
        paths.state_dir.display(),
        if cfg!(windows) {
            " (the Windows one lands at M6)"
        } else {
            ""
        }
    )
}

/// Send one op down whichever route is available.
async fn send(paths: &Paths, route: &Route, op: IpcOp) -> anyhow::Result<IpcResponse> {
    // The id is per-process and only has to be unique within one connection.
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let req = IpcRequest { id, op };
    match route {
        Route::Host => Ok(tornect_platform::ipc::request(&paths.state_dir, &req).await?),
        Route::Offline(ctx) => {
            // The guard blocks (fsync, and the re-auth dialog).
            let ctx = ctx.as_ref();
            let resp = tokio::task::block_in_place(|| dispatch(ctx, req));
            // A host that started while this command ran is what the guard's
            // session check saw (SLICE-D D1); say so, not "a remote session".
            if resp.code == codes::G_REMOTE_SESSION_ACTIVE
                && let Some(holder) = crate::host::HostLock::holder(paths)
            {
                anyhow::bail!(
                    "a Tornect host started for {} ({holder}) while this command ran, and \
                     this command cannot see that host's sessions, so nothing was changed; \
                     run it again and it goes through the host",
                    paths.state_dir.display()
                );
            }
            Ok(resp)
        }
    }
}

/// Turn a failed response into an error the user can act on.
fn require_ok(resp: &IpcResponse) -> anyhow::Result<()> {
    if resp.ok {
        return Ok(());
    }
    let detail = resp.detail.clone().unwrap_or_else(|| "refused".to_owned());
    let hint = match resp.code {
        codes::G_REAUTH_FAILED => {
            "\n  This operation increases access, so it needs OS re-authentication (§B.8.6.2)."
        }
        codes::G_REMOTE_SESSION_ACTIVE => {
            "\n  A remote session is live or ended less than 60 s ago; access cannot be widened \
             while someone may be watching."
        }
        codes::G_STORE_LOCKED => "\n  Another Tornect process holds the store lock.",
        codes::G_KEYSTORE_LOCKED => "\n  The keystore could not be unlocked.",
        _ => "",
    };
    anyhow::bail!("{detail} (0x{:04x}){hint}", resp.code)
}

/// Resolve a device argument: an exact device ID, else a unique fingerprint or
/// label match among the grants this host knows.
async fn resolve_device(paths: &Paths, route: &Route, arg: &str) -> anyhow::Result<DeviceId> {
    if let Ok(id) = arg.parse::<DeviceId>() {
        return Ok(id);
    }
    let resp = send(paths, route, IpcOp::Status).await?;
    require_ok(&resp)?;
    let payload = resp
        .payload
        .as_deref()
        .context("Status returned no payload")?;
    let report: tornect_core::unattended::ipc::StatusReport =
        tornect_core::unattended::ipc::decode_payload(payload)?;
    let needle = arg.to_lowercase();
    let matches: Vec<&tornect_core::unattended::ipc::GrantSummary> = report
        .grants
        .iter()
        .filter(|g| {
            g.label.to_lowercase() == needle
                || g.device.fingerprint().starts_with(&needle)
                || g.device.to_string().starts_with(&needle)
        })
        .collect();
    match matches.as_slice() {
        [one] => Ok(one.device),
        [] => anyhow::bail!(
            "no device matches {arg:?}; `tornect unattended status` lists the ones this host knows"
        ),
        many => {
            let labels: Vec<&str> = many.iter().map(|g| g.label.as_str()).collect();
            anyhow::bail!(
                "{arg:?} matches {} devices ({}); use the full device ID",
                many.len(),
                labels.join(", ")
            )
        }
    }
}

/// Bytes one terminal line may take: [`MAX_CHARS`] characters of up to four
/// UTF-8 bytes each, plus the line ending.
///
/// [`MAX_CHARS`]: tornect_core::unattended::password::MAX_CHARS
#[cfg(unix)]
const LINE_CAP: usize = tornect_core::unattended::password::MAX_CHARS * 4 + 2;

/// Read one line from the terminal **straight off the file descriptor**, into a
/// buffer sized once, up front, and wiped on drop (§B.8.7.2 "all intermediates in
/// Zeroizing").
///
/// Not `std::io::stdin().read_line`: `Stdin` keeps a process-global 8 KiB buffer
/// that is never wiped, and a `String` grown by `read_line` leaves every outgrown
/// copy of the password in freed heap memory (track D S8/S12). A line longer than
/// the buffer is drained to its end and refused: left in the terminal, its tail
/// would be read by the shell as a command once Tornect exits. One byte per
/// `read`, so nothing past the newline is ever consumed, whatever the descriptor
/// (a line is at most a few hundred bytes).
#[cfg(unix)]
fn read_line_unbuffered(fd: &impl rustix::fd::AsFd) -> anyhow::Result<zeroize::Zeroizing<String>> {
    use zeroize::Zeroize as _;

    /// One byte, retrying an interrupted read; `None` at end of input.
    fn read_byte(fd: &impl rustix::fd::AsFd, byte: &mut [u8; 1]) -> anyhow::Result<Option<u8>> {
        loop {
            match rustix::io::read(fd, &mut byte[..]) {
                Ok(0) => return Ok(None),
                Ok(_) => return Ok(Some(byte[0])),
                Err(rustix::io::Errno::INTR) => {}
                Err(e) => return Err(std::io::Error::from(e).into()),
            }
        }
    }

    let mut buf = zeroize::Zeroizing::new(vec![0u8; LINE_CAP]);
    let mut byte = zeroize::Zeroizing::new([0u8; 1]);
    let mut len = 0;
    let line_len = loop {
        let Some(b) = read_byte(fd, &mut byte)? else {
            // End of input without a newline: the line is what was typed.
            break len;
        };
        if b == b'\n' {
            break len;
        }
        if len == buf.len() {
            while let Some(b) = read_byte(fd, &mut byte)? {
                if b == b'\n' {
                    break;
                }
            }
            anyhow::bail!(
                "that line is longer than any password Tornect accepts ({} characters at most)",
                tornect_core::unattended::password::MAX_CHARS
            );
        }
        buf[len] = b;
        len += 1;
    };
    let mut line_end = line_len;
    if line_end > 0 && buf[line_end - 1] == b'\r' {
        line_end -= 1;
    }
    buf[line_end..].zeroize();
    let mut bytes = std::mem::take(&mut *buf);
    bytes.truncate(line_end);
    match String::from_utf8(bytes) {
        Ok(line) => Ok(zeroize::Zeroizing::new(line)),
        Err(e) => {
            e.into_bytes().zeroize();
            anyhow::bail!("the terminal input is not valid UTF-8")
        }
    }
}

/// Read a password from the controlling terminal with echo off (§B.8.7.4:
/// "passwords via TTY prompt, never argv").
///
/// Echo is restored on every exit path, including the error ones — a terminal
/// left with `ECHO` off after a failed prompt is a hostile thing to hand back
/// to someone.
#[cfg(unix)]
fn read_password(prompt: &str) -> anyhow::Result<zeroize::Zeroizing<String>> {
    use std::io::Write as _;

    use rustix::termios::{self, OptionalActions};

    let stdin = std::io::stdin();
    if !termios::isatty(&stdin) {
        anyhow::bail!(
            "a password prompt needs a terminal; run this command interactively \
             (Tornect never accepts a password as an argument)"
        );
    }
    eprint!("{prompt}");
    std::io::stderr().flush()?;

    let original = termios::tcgetattr(&stdin)?;
    let mut quiet = original.clone();
    quiet.local_modes -= termios::LocalModes::ECHO;
    termios::tcsetattr(&stdin, OptionalActions::Flush, &quiet)?;

    let read = read_line_unbuffered(&stdin);

    // Restore before looking at the result.
    let restored = termios::tcsetattr(&stdin, OptionalActions::Flush, &original);
    eprintln!();
    restored?;
    read
}

#[cfg(not(unix))]
fn read_password(_prompt: &str) -> anyhow::Result<zeroize::Zeroizing<String>> {
    anyhow::bail!("the password prompt is implemented for Unix at M1 (docs/PLAN.md §B.8.14 M6)")
}

/// Ask a yes/no question on the terminal (echo on); anything but `y`/`yes` is no.
#[cfg(unix)]
fn confirm(question: &str) -> anyhow::Result<bool> {
    use std::io::Write as _;
    eprint!("{question} [y/N] ");
    std::io::stderr().flush()?;
    let answer = read_line_unbuffered(&std::io::stdin())?;
    Ok(matches!(answer.trim().to_lowercase().as_str(), "y" | "yes"))
}

#[cfg(not(unix))]
fn confirm(_question: &str) -> anyhow::Result<bool> {
    Ok(false)
}

/// What the owner is told about a [`PolicyWarning`] (§B.8.7.2: whitespace is
/// kept, never trimmed, so it is warned about instead).
///
/// [`PolicyWarning`]: tornect_core::unattended::password::PolicyWarning
fn policy_warning_text(w: tornect_core::unattended::password::PolicyWarning) -> &'static str {
    use tornect_core::unattended::password::PolicyWarning;
    match w {
        PolicyWarning::LeadingWhitespace => {
            "it starts with a space; that space is part of the password and must be typed \
             every time"
        }
        PolicyWarning::TrailingWhitespace => {
            "it ends with a space; that space is part of the password and must be typed \
             every time"
        }
    }
}

/// Prompt twice and check §B.8.7.2 locally, as the spec requires: the host
/// never sees the password, so the CLI is the only thing that can enforce the
/// policy.
fn prompt_new_password(
    inputs: &[String],
    min_score: u8,
) -> anyhow::Result<zeroize::Zeroizing<String>> {
    // `min_score` travels over IPC because only the host knows which keystore it
    // ended up with; §B.8.7.2 raises the bar to 4 exactly on a file-keystore
    // host, which is what `check`'s `file_keystore` flag selects.
    let file_keystore = min_score >= 4;
    let refs: Vec<&str> = inputs.iter().map(String::as_str).collect();
    for attempt in 1..=3 {
        let pw = read_password("New unattended password: ")?;
        let normalized = tornect_core::unattended::password::normalize(&pw);
        match tornect_core::unattended::password::check(&normalized, &refs, file_keystore) {
            Ok(checked) => {
                if !checked.warnings.is_empty() {
                    for w in &checked.warnings {
                        eprintln!("  note: {}", policy_warning_text(*w));
                    }
                    if !confirm("Use this password anyway?")? {
                        if attempt == 3 {
                            anyhow::bail!("no password chosen after 3 attempts");
                        }
                        continue;
                    }
                }
            }
            Err(e) => {
                eprintln!("  {e}");
                if attempt == 3 {
                    anyhow::bail!("password policy not met after 3 attempts");
                }
                continue;
            }
        }
        let again = read_password("Repeat it: ")?;
        if tornect_core::unattended::password::normalize(&again) != normalized {
            eprintln!("  the two entries differ");
            if attempt == 3 {
                anyhow::bail!("passwords did not match after 3 attempts");
            }
            continue;
        }
        return Ok(normalized);
    }
    unreachable!("the loop returns or bails")
}

/// Run one `tornect unattended …` command.
pub async fn run_unattended(paths: &Paths, cmd: UnattendedCmd) -> anyhow::Result<()> {
    let route = route(paths).await?;
    match cmd {
        UnattendedCmd::Status { json } => {
            let resp = send(paths, &route, IpcOp::Status).await?;
            require_ok(&resp)?;
            let payload = resp
                .payload
                .as_deref()
                .context("Status returned no payload")?;
            let report: tornect_core::unattended::ipc::StatusReport =
                tornect_core::unattended::ipc::decode_payload(payload)?;
            print_status(&report, json)
        }
        UnattendedCmd::On => {
            let mut resp = send(paths, &route, IpcOp::On).await?;
            require_ok(&resp)?;
            let payload = resp.payload.as_deref().context("On returned no payload")?;
            let card: Result<MasterOnPayload, _> =
                tornect_core::unattended::ipc::decode_payload(payload);
            // The payload is the stop code itself (§B.8.7.2, A14).
            if let Some(p) = resp.payload.as_mut() {
                zeroize::Zeroize::zeroize(p);
            }
            let card = card?;
            println!("Unattended access is ON.");
            println!();
            println!("  EMERGENCY STOP CODE");
            print_secret_line(&format_stop_code(&card.stop_code))?;
            println!();
            println!("  Write this down and keep it away from this computer. Presenting it from");
            println!("  any device turns unattended access off, revokes every grant and ends any");
            println!("  session. It is shown once, works once, and is replaced each time you");
            println!("  turn unattended access on again.");
            Ok(())
        }
        UnattendedCmd::Off => {
            require_ok(&send(paths, &route, IpcOp::Off).await?)?;
            println!(
                "Unattended access is OFF. Grants are kept; nothing can connect without asking."
            );
            Ok(())
        }
        UnattendedCmd::Pause { secs } => {
            let until = wall_now().saturating_add(secs);
            require_ok(&send(paths, &route, IpcOp::Pause { until }).await?)?;
            println!("Unattended access paused for {secs} s.");
            Ok(())
        }
        UnattendedCmd::Grant {
            device,
            preset,
            waive_attended_check,
        } => {
            if waive_attended_check {
                // §B.8.7.4: the waiver is "warned and logged"; the guard logs it.
                eprintln!(
                    "warning: --waive-attended-check skips the rule that this device must \
                     first have had an attended session you watched. The waiver is logged."
                );
            }
            let device = resolve_device(paths, &route, &device).await?;
            register(
                paths,
                &route,
                device,
                Some(preset.into()),
                waive_attended_check,
            )
            .await
        }
        UnattendedCmd::SetPassword { device } => {
            let device = resolve_device(paths, &route, &device).await?;
            register(paths, &route, device, None, false).await
        }
        UnattendedCmd::Enable { device } => {
            let device = resolve_device(paths, &route, &device).await?;
            require_ok(&send(paths, &route, IpcOp::Enable { device }).await?)?;
            println!("Enabled.");
            Ok(())
        }
        UnattendedCmd::Disable { device } => {
            let device = resolve_device(paths, &route, &device).await?;
            require_ok(&send(paths, &route, IpcOp::Disable { device }).await?)?;
            println!("Disabled. The grant and its password are kept.");
            Ok(())
        }
        UnattendedCmd::Revoke { device, all } => {
            if all {
                require_ok(&send(paths, &route, IpcOp::RevokeAll).await?)?;
                println!("Every unattended grant was removed.");
                return Ok(());
            }
            let Some(arg) = device else {
                anyhow::bail!("name a device, or pass --all");
            };
            let device = resolve_device(paths, &route, &arg).await?;
            require_ok(&send(paths, &route, IpcOp::Revoke { device }).await?)?;
            println!("Revoked. That device must be granted access again to connect unattended.");
            Ok(())
        }
        UnattendedCmd::Unlock { device } => {
            let device = resolve_device(paths, &route, &device).await?;
            require_ok(&send(paths, &route, IpcOp::Unlock { device }).await?)?;
            println!("Failure counters cleared.");
            Ok(())
        }
        UnattendedCmd::Suspend { device } => {
            let device = resolve_device(paths, &route, &device).await?;
            let resp = send(paths, &route, IpcOp::Suspend { device }).await?;
            require_ok(&resp)?;
            match resp.detail {
                Some(d) => println!("Suspended ({d})."),
                None => println!("Suspended. Use `resume` to clear it."),
            }
            Ok(())
        }
        UnattendedCmd::Resume { device } => {
            let device = resolve_device(paths, &route, &device).await?;
            require_ok(&send(paths, &route, IpcOp::Resume { device }).await?)?;
            println!("Resumed.");
            Ok(())
        }
        UnattendedCmd::Readiness => {
            let resp = send(paths, &route, IpcOp::Readiness).await?;
            require_ok(&resp)?;
            let payload = resp
                .payload
                .as_deref()
                .context("Readiness returned no payload")?;
            let snap: ReadinessSnapshot = tornect_core::unattended::ipc::decode_payload(payload)?;
            print_readiness(&snap);
            Ok(())
        }
        UnattendedCmd::Log { filter, after } => {
            let resp = send(paths, &route, IpcOp::Log { filter, after }).await?;
            require_ok(&resp)?;
            let payload = resp.payload.as_deref().context("Log returned no payload")?;
            let page: LogPage = tornect_core::unattended::ipc::decode_payload(payload)?;
            for line in &page.lines {
                println!("{line}");
            }
            if let Some(next) = page.next {
                eprintln!("-- more; continue with --after {next}");
            }
            Ok(())
        }
    }
}

/// The two-message registration of §B.8.7.4.
///
/// The password stays in this process: only `reg_request`, `reg_response` and
/// `upload` cross the socket. The host runs one re-authentication dialog, at
/// `RegStart`, and hands back a single-use transaction that `RegFinish` must
/// present within 120 s — so an un-gated `RegStart` can never be used as an
/// OPRF oracle for a credential id.
async fn register(
    paths: &Paths,
    route: &Route,
    device: DeviceId,
    preset: Option<Preset>,
    waive_attended_check: bool,
) -> anyhow::Result<()> {
    // The policy inputs come from the host, because it knows its own name, its
    // onion address and the labels of the devices it has paired.
    let resp = send(paths, route, IpcOp::PolicyInputs).await?;
    require_ok(&resp)?;
    let payload = resp
        .payload
        .as_deref()
        .context("PolicyInputs returned no payload")?;
    let policy: PolicyInputsPayload = tornect_core::unattended::ipc::decode_payload(payload)?;

    let password = prompt_new_password(&policy.user_inputs, policy.min_score)?;

    let (client, reg_request) = tornect_signal::auth::PasswordRegistration::start(&password)
        .map_err(|e| anyhow::anyhow!("starting the registration: {e}"))?;

    let resp = send(
        paths,
        route,
        IpcOp::RegStart {
            device,
            reg_request,
        },
    )
    .await?;
    require_ok(&resp)?;
    let payload = resp
        .payload
        .as_deref()
        .context("RegStart returned no payload")?;
    let started: anyhow::Result<RegStartPayload> =
        tornect_core::unattended::ipc::decode_payload(payload).map_err(Into::into);
    // `reg_txn` is the 120 s capability that lets a `RegFinish` land.
    let mut resp = resp;
    if let Some(p) = resp.payload.as_mut() {
        zeroize::Zeroize::zeroize(p);
    }
    let started = started?;

    // The identifiers must match the ones the login will use (§B.8.4.3), so the
    // host's onion key is part of the record.
    let host_pk = host_onion_pk(paths)?;
    let ids = tornect_signal::auth::identifiers(device.public_key_bytes(), &host_pk);
    let upload = client
        .finish(&password, &started.reg_response, ids)
        .map_err(|e| anyhow::anyhow!("finishing the registration: {e}"))?;
    drop(password);

    let options = GrantOptions {
        waive_attended_precondition: waive_attended_check,
        ..GrantOptions::default()
    };
    let resp = send(
        paths,
        route,
        IpcOp::RegFinish {
            device,
            reg_txn: started.reg_txn,
            upload,
            // `set-password` keeps the existing preset; the guard reads it back
            // from the grant, so the byte sent here is ignored on that path.
            preset: preset.unwrap_or(Preset::MyMachines).wire(),
            options,
        },
    )
    .await?;
    require_ok(&resp)?;
    match preset {
        Some(_) => {
            println!("Granted. That device can now connect without asking, using this password.")
        }
        None => println!("Password changed."),
    }
    Ok(())
}

fn host_onion_pk(paths: &Paths) -> anyhow::Result<[u8; 32]> {
    use tornect_core::keystore::{FileSecretStore, load_or_create_host_identity};
    let secrets = FileSecretStore::open(paths.keys_dir())?;
    let (host, _) = load_or_create_host_identity(&secrets)?;
    Ok(*host.id().public_key_bytes())
}

/// `xxxx-xxxx-xxxx-xxxx …` — grouped so it can be read aloud and written down.
/// Built in one buffer sized up front and wiped on drop: no intermediate copy of
/// the code is left behind (§B.8.7.2, A14).
fn format_stop_code(code: &[u8; 16]) -> zeroize::Zeroizing<String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = zeroize::Zeroizing::new(String::with_capacity(48));
    for (i, b) in code.iter().enumerate() {
        if i > 0 && i % 2 == 0 {
            out.push('-');
        }
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    out
}

/// Print `  <secret>\n` straight to the stdout descriptor: `std`'s stdout buffer
/// is process-global and never wiped (track D S12).
fn print_secret_line(secret: &str) -> anyhow::Result<()> {
    use std::io::Write as _;
    let mut line = zeroize::Zeroizing::new(String::with_capacity(secret.len() + 3));
    line.push_str("  ");
    line.push_str(secret);
    line.push('\n');
    std::io::stdout().flush()?;
    #[cfg(unix)]
    {
        let stdout = std::io::stdout();
        let mut rest = line.as_bytes();
        while !rest.is_empty() {
            match rustix::io::write(&stdout, rest) {
                Ok(n) => rest = &rest[n..],
                Err(rustix::io::Errno::INTR) => {}
                Err(e) => return Err(std::io::Error::from(e).into()),
            }
        }
    }
    #[cfg(not(unix))]
    {
        let mut out = std::io::stdout();
        out.write_all(line.as_bytes())?;
        out.flush()?;
    }
    Ok(())
}

fn print_status(
    report: &tornect_core::unattended::ipc::StatusReport,
    json: bool,
) -> anyhow::Result<()> {
    if json {
        let grants: Vec<serde_json::Value> = report
            .grants
            .iter()
            .map(|g| {
                serde_json::json!({
                    "device": g.device.to_string(),
                    "fingerprint": g.device.fingerprint(),
                    "label": g.label,
                    "preset": g.preset,
                    "mode": g.mode,
                    "state": g.state,
                    "expires_at": g.expires_at,
                    "last_used": g.last_used,
                    "failures_since_unlock": g.failures_since_unlock,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "enabled": report.enabled,
                "paused_until": report.paused_until,
                "keystore": if report.keystore_kind == 1 { "file" } else { "os_keychain" },
                "grants": grants,
            }))?
        );
        return Ok(());
    }
    println!(
        "Unattended access: {}",
        if report.enabled { "ON" } else { "OFF" }
    );
    if let Some(until) = report.paused_until {
        let left = until.saturating_sub(wall_now());
        println!("  paused for another {left} s");
    }
    println!(
        "Keystore: {}",
        if report.keystore_kind == 1 {
            "file"
        } else {
            "OS keychain"
        }
    );
    if report.grants.is_empty() {
        println!("No device can connect without asking.");
        return Ok(());
    }
    println!("{} device(s):", report.grants.len());
    for g in &report.grants {
        println!(
            "  {:<24} {:<14} {:<12} fail={} {}",
            g.label,
            g.state,
            match g.mode {
                1 => "view-only",
                _ => "control",
            },
            g.failures_since_unlock,
            g.device.fingerprint(),
        );
    }
    Ok(())
}

fn print_readiness(snap: &ReadinessSnapshot) {
    use tornect_core::unattended::readiness::Probe;
    println!("Readiness (M1: every probe reads Unknown until the platform backends land at M6)");
    for (name, probe) in snap.fields() {
        let text = match probe {
            Probe::Ok => "ok".to_owned(),
            Probe::Warn(m) => format!("warn: {m}"),
            Probe::Fail(m) => format!("FAIL: {m}"),
            Probe::Unknown => "unknown".to_owned(),
        };
        println!("  {name:<18} {text}");
    }
    if snap.badge() {
        println!();
        println!("At least one row is not Ok; the host raises its not-ready badge.");
    }
}

// ---------------------------------------------------------------------------
// Entry points called from main.rs
// ---------------------------------------------------------------------------

fn runtime() -> anyhow::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("creating the tokio runtime")
}

/// `tornect unattended …`
pub fn unattended(paths: &Paths, cmd: UnattendedCmd) -> anyhow::Result<()> {
    runtime()?.block_on(run_unattended(paths, cmd))
}

/// `tornect devices` — the paired devices, and which of them may connect
/// without asking.
///
/// Pairing lives in `trusted-devices.toml` and unattended grants in the
/// encrypted store; a device can be paired without a grant, and §B.8's hard rule
/// 2 means it can never have a grant without being paired. Showing both in one
/// place is the only way to see that relationship.
pub fn devices(paths: &Paths, json: bool) -> anyhow::Result<()> {
    runtime()?.block_on(async move {
        let trusted =
            tornect_signal::pairing::TrustedDeviceStore::open(paths.trusted_devices_file())?
                .snapshot();
        let route = route(paths).await?;
        let grants: std::collections::HashMap<DeviceId, String> =
            match send(paths, &route, IpcOp::Status).await {
                Ok(resp) if resp.ok => resp
                    .payload
                    .as_deref()
                    .and_then(|p| {
                        tornect_core::unattended::ipc::decode_payload::<
                            tornect_core::unattended::ipc::StatusReport,
                        >(p)
                        .ok()
                    })
                    .map(|r| r.grants.into_iter().map(|g| (g.device, g.state)).collect())
                    .unwrap_or_default(),
                // No store yet, or it is failed closed: pairings are still worth
                // listing, so this is a missing column rather than an error.
                _ => std::collections::HashMap::new(),
            };

        let paired = &trusted.devices;
        if json {
            let rows: Vec<serde_json::Value> = paired
                .iter()
                .map(|d| {
                    serde_json::json!({
                        "device": d.device.to_string(),
                        "fingerprint": d.device.fingerprint(),
                        "label": d.label,
                        "paired_at": d.paired_at,
                        "last_seen": d.last_seen,
                        "unattended": grants.get(&d.device),
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&rows)?);
            return Ok(());
        }
        if paired.is_empty() {
            println!(
                "No paired devices. Pair one by connecting to this host and confirming the code."
            );
            return Ok(());
        }
        println!("{} paired device(s):", paired.len());
        for d in paired {
            let ua = grants.get(&d.device).map_or("—", String::as_str);
            println!("  {:<24} {:<14} {}", d.label, ua, d.device.fingerprint());
        }
        Ok(())
    })
}

/// `tornect panic`
pub fn panic_now(paths: &Paths) -> anyhow::Result<()> {
    runtime()?.block_on(async move {
        match probe(paths).await {
            Probe::Host => {}
            Probe::Unreachable(holder) => anyhow::bail!(
                "{}; press Ctrl-C in its terminal to end its sessions",
                unreachable_host(paths, &holder)
            ),
            Probe::NoHost => anyhow::bail!(
                "no Tornect host is running for {}, so there is no session to end",
                paths.state_dir.display()
            ),
        }
        let resp = send(paths, &Route::Host, IpcOp::Panic).await?;
        // A panic that could not run must be loud, not swallowed.
        require_ok(&resp)?;
        // Only this state directory's host: another home's is not reached
        // (SLICE-C3 C3-4).
        let home = paths.state_dir.display();
        match resp.detail {
            Some(d) => println!("Sessions ended on the host for {home}. {d}"),
            None => println!("Sessions ended on the host for {home}."),
        }
        Ok(())
    })
}

/// `tornect service install|uninstall|status`
pub fn service(paths: &Paths, cmd: ServiceCmd) -> anyhow::Result<()> {
    runtime()?.block_on(async move {
        let route = route(paths).await?;
        let op = match cmd {
            ServiceCmd::Install { elevated } => IpcOp::ServiceInstall { elevated },
            ServiceCmd::Uninstall => IpcOp::ServiceUninstall,
            ServiceCmd::Status => {
                println!(
                    "Autostart registration is reported by the platform backends, which land at \
                     M6 (docs/PLAN.md §B.8.14)."
                );
                return Ok(());
            }
        };
        require_ok(&send(paths, &route, op).await?)
    })
}

/// `tornect backup export|import`
pub fn backup(paths: &Paths, cmd: BackupCmd) -> anyhow::Result<()> {
    runtime()?.block_on(async move {
        let route = route(paths).await?;
        let op = match cmd {
            BackupCmd::Export { path } => IpcOp::BackupExport { path },
            BackupCmd::Import { path } => IpcOp::BackupImport { path },
        };
        require_ok(&send(paths, &route, op).await?)
    })
}

#[cfg(test)]
mod tests {
    use tornect_core::keystore::FileSecretStore;
    use tornect_core::unattended::clock::SystemClock;
    use tornect_core::unattended::guard::{
        AllowAllPaired, AllowAllReAuth, DenyAllReAuth, NoSessionActivity,
    };
    use tornect_core::unattended::ipc::{StatusReport, decode_payload};

    use super::*;

    const HOST_PK: [u8; 32] = [0x42; 32];

    struct Env {
        _tmp: tempfile::TempDir,
        ctx: HostContext,
    }

    /// A context wired like the offline CLI, but with re-authentication
    /// scripted rather than asking a human.
    fn env(reauth_allows: bool) -> Env {
        let reauth: Arc<dyn tornect_core::unattended::guard::ReAuth> = if reauth_allows {
            Arc::new(AllowAllReAuth::default())
        } else {
            Arc::new(DenyAllReAuth)
        };
        env_with(
            tempfile::tempdir().unwrap(),
            reauth,
            Arc::new(NoSessionActivity),
        )
    }

    /// [`env`] in `tmp`, with the given re-authentication and the given view
    /// of remote sessions.
    fn env_with(
        tmp: tempfile::TempDir,
        reauth: Arc<dyn tornect_core::unattended::guard::ReAuth>,
        activity: Arc<dyn RemoteSessionActivity>,
    ) -> Env {
        let paths = Paths::from_home(tmp.path());
        paths.ensure().unwrap();
        let secrets = Arc::new(FileSecretStore::open(paths.keys_dir()).unwrap());
        let log = SessionLog::new(paths.sessions_log());
        let store = GrantStore::open(
            &paths,
            Arc::clone(&secrets) as Arc<dyn tornect_core::SecretStore>,
            Arc::new(SystemClock::default()),
            log.clone(),
        )
        .unwrap();
        let guard = MutationGuard::new(store, reauth, activity)
            .with_paired_devices(Arc::new(AllowAllPaired))
            .with_server_setup_source(Arc::new(
                tornect_signal::unattended::OpaqueServerSetupSource,
            ));
        Env {
            _tmp: tmp,
            ctx: HostContext {
                guard: Arc::new(guard),
                host_onion_pk: HOST_PK,
                readiness: ReadinessSnapshot::unknown(),
                user_inputs: vec!["tornect".to_owned()],
                kill: None,
                log,
            },
        }
    }

    fn go(ctx: &HostContext, op: IpcOp) -> IpcResponse {
        dispatch(ctx, IpcRequest { id: 1, op })
    }

    /// Track D S5: the offline route loads the store as the offline CLI
    /// (§B.8.5.1: no settlement, no decay, nothing written at load), and only the
    /// host route loads it as the host. The load rules themselves are pinned in
    /// `tornect-core`; this pins which route gets which. Only the host route
    /// has a kill switch, and its `Panic` fires the switch it was given — the
    /// one `tornect host` arms every stream with.
    #[tokio::test]
    async fn only_the_host_route_loads_the_store_as_the_host() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        {
            let offline = offline_context(&paths).unwrap();
            assert_eq!(offline.guard.store().mode(), LoadMode::Offline);
            assert!(
                offline.kill.is_none(),
                "the offline route has no session to end"
            );
        }
        // Dropping the offline context released the store lock.
        let kill = KillSwitch::new();
        let host = host_context(&paths, Arc::new(NoSessionActivity), kill.clone()).unwrap();
        assert_eq!(host.guard.store().mode(), LoadMode::Host);
        let mut armed = kill.arm();
        assert!(go(&host, IpcOp::Panic).ok);
        let fired = tokio::time::timeout(std::time::Duration::from_secs(1), armed.killed()).await;
        assert_eq!(fired.ok(), Some(tornect_signal::messages::bye::PANIC));
    }

    /// SLICE-B2 B2-2: no command runs the guard offline beside a live host that
    /// does not answer (Windows until M6, or a failed bind). That guard cannot
    /// see the host's sessions: before, `unattended on` went through it and
    /// skipped the §B.8.6.2 live-session gate.
    #[tokio::test]
    async fn no_command_runs_offline_beside_a_host_that_does_not_answer() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        paths.ensure().unwrap();
        let host = crate::host::HostLock::acquire(&paths).unwrap();
        let refused = match route(&paths).await {
            Ok(Route::Offline(_)) => panic!("took the offline route beside a live host"),
            Ok(Route::Host) => panic!("nothing is listening"),
            Err(e) => e.to_string(),
        };
        assert!(
            refused.contains("a Tornect host is running for"),
            "{refused}"
        );
        drop(host);
        assert!(matches!(route(&paths).await, Ok(Route::Offline(_))));
    }

    /// A re-auth dialog during which a `tornect host` starts: the host takes
    /// its lock on dialog number `on_call`, and the dialog then allows.
    struct HostStartsDuringDialog {
        paths: Paths,
        on_call: usize,
        calls: std::sync::atomic::AtomicUsize,
        host: std::sync::Mutex<Option<crate::host::HostLock>>,
    }

    impl HostStartsDuringDialog {
        fn new(paths: &Paths, on_call: usize) -> Self {
            Self {
                paths: paths.clone(),
                on_call,
                calls: std::sync::atomic::AtomicUsize::new(0),
                host: std::sync::Mutex::new(None),
            }
        }
    }

    impl tornect_core::unattended::guard::ReAuth for HostStartsDuringDialog {
        fn reauthenticate(
            &self,
            _op: &str,
        ) -> Result<(), tornect_core::unattended::guard::ReAuthError> {
            let call = self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if call == self.on_call {
                let lock = crate::host::HostLock::acquire(&self.paths).unwrap();
                *self.host.lock().unwrap() = Some(lock);
            }
            Ok(())
        }
    }

    /// SLICE-D D1: a command routed offline before any host ran keeps its
    /// offline guard for its whole run. A host that starts while `On`'s
    /// re-auth dialog is open must stop it: before, the guard asked
    /// `NoSessionActivity` and `On` handed out a stop code beside the host's
    /// live sessions.
    #[test]
    fn a_host_that_starts_during_the_dialog_stops_an_offline_on() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        let reauth = Arc::new(HostStartsDuringDialog::new(&paths, 0));
        let env = env_with(tmp, reauth, offline_activity(&paths));
        let resp = go(&env.ctx, IpcOp::On);
        assert!(
            !resp.ok,
            "On went through beside a host that started during its dialog"
        );
        assert_eq!(
            resp.code,
            codes::G_REMOTE_SESSION_ACTIVE,
            "{:?}",
            resp.detail
        );
        assert!(resp.payload.is_none(), "no stop code");
        assert!(!enabled(&env.ctx));
    }

    /// SLICE-D D1, registration: a host that starts between `RegStart` and
    /// `RegFinish` (while the user finishes the exchange) stops the grant at
    /// `RegFinish`'s last check before the write.
    #[test]
    fn a_host_that_starts_before_reg_finish_stops_an_offline_grant() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        let env = env_with(
            tmp,
            Arc::new(AllowAllReAuth::default()),
            offline_activity(&paths),
        );
        assert!(go(&env.ctx, IpcOp::On).ok);
        let device = DeviceId::from_bytes(
            *ed25519_dalek::SigningKey::from_bytes(&[9u8; 32])
                .verifying_key()
                .as_bytes(),
        );
        let password = "quiet verdant otter lantern zephyr";
        let (client, reg_request) =
            tornect_signal::auth::PasswordRegistration::start(password).unwrap();
        let resp = go(
            &env.ctx,
            IpcOp::RegStart {
                device,
                reg_request,
            },
        );
        assert!(resp.ok, "{:?}", resp.detail);
        let started: RegStartPayload = decode_payload(resp.payload.as_deref().unwrap()).unwrap();

        let host = crate::host::HostLock::acquire(&paths).unwrap();
        let ids = tornect_signal::auth::identifiers(device.public_key_bytes(), &HOST_PK);
        let upload = client.finish(password, &started.reg_response, ids).unwrap();
        let resp = go(
            &env.ctx,
            IpcOp::RegFinish {
                device,
                reg_txn: started.reg_txn,
                upload,
                preset: Preset::HeadlessBox.wire(),
                options: GrantOptions::default(),
            },
        );
        assert!(!resp.ok, "the grant was written beside a host");
        assert_eq!(
            resp.code,
            codes::G_REMOTE_SESSION_ACTIVE,
            "{:?}",
            resp.detail
        );
        assert!(env.ctx.guard.store().grant(&device).is_none());
        drop(host);
    }

    /// SLICE-D D1, as the CLI runs it: `route()` picks the offline route while
    /// no host runs, a host then takes its lock, and `On` down that route is
    /// refused with `G_REMOTE_SESSION_ACTIVE` and blamed on the host. The two
    /// tests above build their guard from `offline_activity` themselves, so
    /// only this one sees what `offline_context` wires in.
    #[test]
    fn the_offline_route_counts_a_host_that_started_as_a_live_session() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        let rt = runtime().unwrap();
        let picked = rt.block_on(route(&paths)).unwrap();
        let Route::Offline(ctx) = &picked else {
            panic!("no host runs yet, so the route is offline");
        };
        let host = crate::host::HostLock::acquire(&paths).unwrap();
        let resp = go(ctx, IpcOp::On);
        assert!(!resp.ok, "On went through beside a host that started");
        assert_eq!(
            resp.code,
            codes::G_REMOTE_SESSION_ACTIVE,
            "{:?}",
            resp.detail
        );
        assert!(resp.payload.is_none(), "no stop code");
        assert!(!enabled(ctx));
        let said = rt
            .block_on(send(&paths, &picked, IpcOp::On))
            .unwrap_err()
            .to_string();
        assert!(said.contains("while this command ran"), "{said}");
        drop(host);
    }

    fn enabled(ctx: &HostContext) -> bool {
        let resp = go(ctx, IpcOp::Status);
        let report: StatusReport = decode_payload(resp.payload.as_deref().unwrap()).unwrap();
        report.enabled
    }

    /// Track D S1, host side: when `On`'s answer cannot be delivered, its undo
    /// turns unattended access back off and retires the stop code nobody saw.
    #[test]
    fn an_undelivered_stop_code_turns_unattended_access_back_off() {
        let Env { _tmp, ctx } = env(true);
        let ctx = Arc::new(ctx);
        let Reply {
            response,
            on_undelivered,
        } = reply(
            &ctx,
            IpcRequest {
                id: 1,
                op: IpcOp::On,
            },
        );
        assert!(response.ok, "{:?}", response.detail);
        assert!(enabled(&ctx));
        let card: MasterOnPayload = decode_payload(response.payload.as_deref().unwrap()).unwrap();

        on_undelivered.expect("`On` carries an undo")();

        assert!(
            !enabled(&ctx),
            "access must not stay on under an unseen stop code"
        );
        let token = tornect_core::unattended::guard::stop_token(&HOST_PK, &card.stop_code);
        assert!(
            !ctx.guard.store().stop_token_matches(&token),
            "the undelivered code is retired"
        );
        let logged = ctx.log.read_all().unwrap().into_iter().any(|r| {
            r.event == tornect_core::session_log::SessionEvent::UnattendedDisabled
                && r.reason.as_deref() == Some("stop code not delivered")
        });
        assert!(logged, "the reason is in sessions.log");
    }

    /// Track D S9/S11: the `zxcvbn` inputs carry the labels of paired devices, so
    /// a password built around a device's name scores as guessable.
    #[test]
    fn policy_inputs_include_paired_device_labels() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        paths.ensure().unwrap();
        tornect_signal::pairing::TrustedDeviceStore::open(paths.trusted_devices_file())
            .unwrap()
            .pin(DeviceId::from_bytes([7u8; 32]), "Laptop-of-Ana")
            .unwrap();
        let ctx = offline_context(&paths).unwrap();
        assert!(
            ctx.user_inputs.iter().any(|i| i == "Laptop-of-Ana"),
            "{:?}",
            ctx.user_inputs
        );
        assert!(ctx.user_inputs.iter().any(|i| i == "tornect"));
    }

    /// Track D S9/S11: whitespace the policy keeps is explained, not dropped.
    #[test]
    fn whitespace_warnings_are_explained() {
        use tornect_core::unattended::password::{PolicyWarning, check};
        let checked = check(" quiet verdant otter lantern zephyr ", &[], false).unwrap();
        assert_eq!(
            checked.warnings,
            vec![
                PolicyWarning::LeadingWhitespace,
                PolicyWarning::TrailingWhitespace
            ]
        );
        for w in checked.warnings {
            assert!(policy_warning_text(w).contains("space"));
        }
    }

    /// Track D S8/S12: the unbuffered reader returns one line without its ending,
    /// and leaves the next line where it was.
    #[cfg(unix)]
    #[test]
    fn the_unbuffered_reader_takes_exactly_one_line() {
        use std::io::Write as _;
        let (mut tx, rx) = std::os::unix::net::UnixStream::pair().unwrap();
        tx.write_all(b"quiet verdant otter\r\nnext\n").unwrap();
        // Both lines are already buffered in the socket; the reader must take
        // the first and leave the second where it was.
        let first = read_line_unbuffered(&rx).unwrap();
        assert_eq!(first.as_str(), "quiet verdant otter");
        assert_eq!(read_line_unbuffered(&rx).unwrap().as_str(), "next");
    }

    /// Track D S8/S12: an over-long line is refused *and drained*: its tail must
    /// not be left for the shell to read as a command after Tornect exits.
    #[cfg(unix)]
    #[test]
    fn an_over_long_line_is_refused_and_drained() {
        use std::io::Write as _;
        let (mut tx, rx) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut long = vec![b'x'; LINE_CAP + 300];
        long.push(b'\n');
        tx.write_all(&long).unwrap();
        tx.write_all(b"after\n").unwrap();
        drop(tx);
        let err = read_line_unbuffered(&rx).unwrap_err();
        assert!(err.to_string().contains("longer than"), "{err}");
        assert_eq!(read_line_unbuffered(&rx).unwrap().as_str(), "after");
    }

    /// Track D S12: the stop code is grouped as before, from one wiped buffer.
    #[test]
    fn the_stop_code_prints_in_groups_of_four() {
        let code: [u8; 16] = core::array::from_fn(|i| u8::try_from(i * 17).unwrap());
        assert_eq!(
            format_stop_code(&code).as_str(),
            "0011-2233-4455-6677-8899-aabb-ccdd-eeff"
        );
    }

    /// Only `On` carries an undo; a refused `On` needs none.
    #[test]
    fn only_a_successful_on_carries_an_undo() {
        let Env {
            _tmp: _allow_home,
            ctx,
        } = env(true);
        let allow = Arc::new(ctx);
        for op in [IpcOp::Status, IpcOp::Off, IpcOp::PolicyInputs] {
            let name = op.name();
            assert!(
                reply(&allow, IpcRequest { id: 1, op })
                    .on_undelivered
                    .is_none(),
                "{name}"
            );
        }
        let Env {
            _tmp: _deny_home,
            ctx,
        } = env(false);
        let deny = Arc::new(ctx);
        let r = reply(
            &deny,
            IpcRequest {
                id: 1,
                op: IpcOp::On,
            },
        );
        assert!(!r.response.ok);
        assert!(r.on_undelivered.is_none());
    }

    /// `Status` works before anything is enabled, and reports the truth.
    #[test]
    fn status_on_a_fresh_host_reports_off_with_no_grants() {
        let env = env(true);
        let resp = go(&env.ctx, IpcOp::Status);
        assert!(resp.ok, "{:?}", resp.detail);
        let report: StatusReport = decode_payload(resp.payload.as_deref().unwrap()).unwrap();
        assert!(!report.enabled);
        assert!(report.grants.is_empty());
    }

    /// `On` returns the emergency stop card in the **payload**, never in
    /// `detail` — `detail` is a human-readable string that reaches logs and
    /// error messages, and this is a 16-byte secret.
    #[test]
    fn master_on_returns_the_stop_code_in_the_payload_not_the_detail() {
        let env = env(true);
        let resp = go(&env.ctx, IpcOp::On);
        assert!(resp.ok, "{:?}", resp.detail);
        let card: MasterOnPayload = decode_payload(resp.payload.as_deref().unwrap()).unwrap();
        assert_ne!(card.stop_code, [0u8; 16], "a real code, not a placeholder");
        assert!(
            resp.detail.is_none(),
            "the stop code must not leak into `detail`: {:?}",
            resp.detail
        );
        // And it is the code the store will actually match.
        let token = tornect_core::unattended::guard::stop_token(&HOST_PK, &card.stop_code);
        assert!(env.ctx.guard.store().stop_token_matches(&token));
    }

    /// Every access-increasing op is refused when re-authentication fails, with
    /// the documented `G_REAUTH_FAILED` code rather than a generic error.
    #[test]
    fn access_increasing_ops_are_refused_without_reauth() {
        let env = env(false);
        let resp = go(&env.ctx, IpcOp::On);
        assert!(!resp.ok);
        assert_eq!(resp.code, codes::G_REAUTH_FAILED, "{:?}", resp.detail);
    }

    /// A deny-direction op does **not** need re-authentication: §B.8.6.2 gates
    /// widening, not closing. `master_off` with a refusing backend must still
    /// work — the opposite would leave a user unable to shut access off.
    #[test]
    fn deny_direction_ops_work_without_reauth() {
        let allow = env(true);
        assert!(go(&allow.ctx, IpcOp::On).ok);
        // Same store, a guard whose re-auth always fails.
        let deny = MutationGuard::new(
            allow.ctx.guard.store().clone(),
            Arc::new(DenyAllReAuth),
            Arc::new(NoSessionActivity),
        );
        let ctx = HostContext {
            guard: Arc::new(deny),
            host_onion_pk: HOST_PK,
            readiness: ReadinessSnapshot::unknown(),
            user_inputs: Vec::new(),
            kill: None,
            log: allow.ctx.log.clone(),
        };
        let resp = go(&ctx, IpcOp::Off);
        assert!(
            resp.ok,
            "turning access OFF must never need a dialog: {resp:?}"
        );
    }

    /// An op tag this build does not know is answered `E_UNKNOWN_KIND`, not
    /// dropped — a version-skewed CLI must see a code rather than hang.
    #[test]
    fn an_unknown_op_is_answered() {
        let env = env(true);
        let resp = go(&env.ctx, IpcOp::Unknown(4242));
        assert!(!resp.ok);
        assert_eq!(resp.code, codes::E_UNKNOWN_KIND);
    }

    /// The operations §B.8.14 schedules for later report that plainly instead of
    /// returning `ok` for something that did not happen — but they still run the
    /// guard's authorisation and log line first.
    #[test]
    fn deferred_operations_say_so_rather_than_faking_success() {
        let env = env(true);
        for op in [
            IpcOp::ServiceInstall { elevated: false },
            IpcOp::ServiceUninstall,
            IpcOp::BackupExport {
                path: "/tmp/x".to_owned(),
            },
        ] {
            let name = op.name();
            let resp = go(&env.ctx, op);
            assert!(!resp.ok, "{name} must not report success");
            let detail = resp.detail.unwrap_or_default();
            assert!(
                detail.contains("M6") || detail.contains("M8"),
                "{name} should say which milestone delivers it: {detail}"
            );
        }
    }

    /// `Panic` with no host running has nothing to end and says so.
    #[test]
    fn panic_offline_has_nothing_to_end() {
        let env = env(true);
        let resp = go(&env.ctx, IpcOp::Panic);
        assert!(!resp.ok);
        assert_eq!(resp.code, codes::G_PRECONDITION);
    }

    /// `PolicyInputs` carries the §B.8.7.2 minimum score, which is 4 on a
    /// file-keystore host — this one is.
    #[test]
    fn policy_inputs_demand_score_four_on_a_file_keystore() {
        let env = env(true);
        let resp = go(&env.ctx, IpcOp::PolicyInputs);
        assert!(resp.ok);
        let p: PolicyInputsPayload = decode_payload(resp.payload.as_deref().unwrap()).unwrap();
        assert_eq!(p.min_score, 4);
        assert!(p.user_inputs.iter().any(|i| i == "tornect"));
    }

    /// `RegFinish` without a live transaction is refused `G_NO_TXN` — the rule
    /// that stops an un-gated `RegStart` becoming an OPRF oracle.
    #[test]
    fn reg_finish_without_a_transaction_is_refused() {
        let env = env(true);
        assert!(go(&env.ctx, IpcOp::On).ok);
        let resp = go(
            &env.ctx,
            IpcOp::RegFinish {
                device: DeviceId::from_bytes([7u8; 32]),
                reg_txn: [0u8; 16],
                upload: [0u8; 192],
                preset: 0,
                options: GrantOptions::default(),
            },
        );
        assert!(!resp.ok);
        assert_eq!(resp.code, codes::G_NO_TXN, "{:?}", resp.detail);
    }

    /// The whole §B.8.7.4 registration exchange, end to end through `dispatch`:
    /// `RegStart` → the client's OPAQUE finish → `RegFinish` → a grant that a
    /// real login can open. This is the test that would catch the
    /// upload-is-not-the-record class of mistake, because the record it stores
    /// is exercised by an actual `HostLogin`.
    #[test]
    fn a_registration_over_the_dispatch_produces_a_usable_grant() {
        let env = env(true);
        assert!(go(&env.ctx, IpcOp::On).ok);
        let device = DeviceId::from_bytes(
            *ed25519_dalek::SigningKey::from_bytes(&[9u8; 32])
                .verifying_key()
                .as_bytes(),
        );
        let password = "quiet verdant otter lantern zephyr";

        let (client, reg_request) =
            tornect_signal::auth::PasswordRegistration::start(password).unwrap();
        let resp = go(
            &env.ctx,
            IpcOp::RegStart {
                device,
                reg_request,
            },
        );
        assert!(resp.ok, "{:?}", resp.detail);
        let started: RegStartPayload = decode_payload(resp.payload.as_deref().unwrap()).unwrap();

        let ids = tornect_signal::auth::identifiers(device.public_key_bytes(), &HOST_PK);
        let upload = client.finish(password, &started.reg_response, ids).unwrap();

        let resp = go(
            &env.ctx,
            IpcOp::RegFinish {
                device,
                reg_txn: started.reg_txn,
                upload,
                preset: Preset::HeadlessBox.wire(),
                options: GrantOptions::default(),
            },
        );
        assert!(resp.ok, "{:?}", resp.detail);

        // The stored record must be one a real login can open.
        let grant = env.ctx.guard.store().grant(&device).expect("a grant");
        let tornect_core::unattended::grant::AuthRecord::Opaque { record } = &grant.auth else {
            panic!("expected an OPAQUE record");
        };
        let setup_bytes = env.ctx.guard.store().server_setup().unwrap();
        let setup = tornect_signal::auth::parse_server_setup(&setup_bytes).unwrap();
        let stored = tornect_signal::auth::parse_record(record).expect("a parseable record");
        let (state, ke1) = tornect_signal::auth::ClientLogin::start(password).unwrap();
        let ctx_bytes = tornect_signal::auth::context(&[0x33; 32], 1, 0);
        let (host_login, ke2) = tornect_signal::auth::HostLogin::start(
            &setup,
            &stored,
            &ke1,
            device.public_key_bytes(),
            &ctx_bytes,
            ids,
        )
        .expect("the host can start a login against the stored record");
        let out = state
            .finish(password, &ke2, &ctx_bytes, ids)
            .expect("the client's password opens it");
        let host_key = host_login.finish(&out.ke3, &ctx_bytes, ids).expect("F2");
        assert_eq!(
            host_key.as_slice(),
            out.session_key.as_slice(),
            "both sides must derive the same key from a grant created over IPC"
        );
    }
}
