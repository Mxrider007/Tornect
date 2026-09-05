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
    ExternalOp, GuardError, MutationGuard, NoSessionActivity, SuspendOutcome,
};
use tornect_core::unattended::ipc::{
    GrantOptions, IpcOp, IpcRequest, IpcResponse, LogPage, MasterOnPayload, PolicyInputsPayload,
    RegStartPayload, codes, encode_payload,
};
use tornect_core::unattended::readiness::ReadinessSnapshot;
use tornect_core::unattended::store::GrantStore;
use tornect_core::{Config, Paths};

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
    pub kill: Option<tornect_signal::fsm::host::KillSwitch>,
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
            // kill switch does; suspending the grant behind a *live* session
            // needs to know which grant that is, and `tornect-session` owns
            // live sessions from M4. So M1 ends what it can reach and says so
            // rather than suspending an arbitrary grant.
            match &ctx.kill {
                Some(k) => {
                    k.kill(tornect_signal::messages::bye::PANIC);
                    let mut r = IpcResponse::ok(id);
                    r.detail = Some(
                        "handshakes ended; suspending the grant behind a live media session \
                         lands at M4 (docs/PLAN.md §B.8.14)"
                            .to_owned(),
                    );
                    r
                }
                None => IpcResponse::fail(
                    id,
                    codes::G_PRECONDITION,
                    "this process serves no handshakes, so there is nothing to end \
                     (the host FSM is not wired into `tornect host` yet — docs/PLAN.md \
                     §B.8.14 M1)",
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

/// Serve the endpoint for the host role until the task is dropped.
pub async fn serve(ctx: Arc<HostContext>, paths: &Paths) -> anyhow::Result<()> {
    let endpoint = tornect_platform::ipc::Endpoint::bind(&paths.state_dir)
        .await
        .context("binding the IPC endpoint")?;
    tracing::info!(path = %endpoint.path().display(), "IPC endpoint listening");
    endpoint
        .serve(|req| {
            let ctx = Arc::clone(&ctx);
            async move {
                // Guard calls are blocking (fsync, and the re-auth dialog):
                // off the reactor they go.
                tokio::task::spawn_blocking(move || dispatch(&ctx, req))
                    .await
                    .unwrap_or_else(|e| {
                        IpcResponse::fail(
                            0,
                            codes::G_PRECONDITION,
                            format!("dispatch panicked: {e}"),
                        )
                    })
            }
        })
        .await
        .context("serving IPC")
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
/// other mutation". The store's advisory lock is what makes the two mutually
/// exclusive — a running host holds it, so the offline route can only ever be
/// taken when there is genuinely no host to talk to.
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
/// Identical to the offline one today, and deliberately so: the same
/// [`dispatch`] runs behind both routes. It gains `kill` — and with it a working
/// `Panic` — when the host FSM is wired into `tornect host` (§B.8.14 M1,
/// outstanding).
pub fn host_context(paths: &Paths) -> anyhow::Result<HostContext> {
    offline_context(paths)
}

/// Build the offline context: the same guard the host would hold, minus the
/// live-session seams there is nothing to fill.
///
/// Note the side effect: this creates the host identity if none exists, because
/// `master_on` needs the onion key to compute the stop token. `tornect id` does
/// the same and says so; here it happens on the first `tornect unattended`
/// command of any kind, including a read-only one.
fn offline_context(paths: &Paths) -> anyhow::Result<HostContext> {
    use tornect_core::keystore::{FileSecretStore, load_or_create_host_identity};
    use tornect_core::unattended::clock::SystemClock;
    use tornect_core::unattended::guard::{FilePairedDevices, SessionLogHistory};

    paths.ensure()?;
    let secrets = Arc::new(FileSecretStore::open(paths.keys_dir())?);
    let (host, _) = load_or_create_host_identity(&*secrets)?;
    let log = SessionLog::new(paths.sessions_log());
    let store = GrantStore::open(
        paths,
        Arc::clone(&secrets) as Arc<dyn tornect_core::SecretStore>,
        Arc::new(SystemClock::default()),
        log.clone(),
    )?;
    let guard = MutationGuard::new(store, reauth_backend(), Arc::new(NoSessionActivity))
        .with_paired_devices(Arc::new(FilePairedDevices::new(
            paths.trusted_devices_file(),
        )))
        .with_attended_history(Arc::new(SessionLogHistory::new(log.clone())))
        .with_server_setup_source(Arc::new(
            tornect_signal::unattended::OpaqueServerSetupSource,
        ));
    Ok(HostContext {
        guard: Arc::new(guard),
        host_onion_pk: *host.id().public_key_bytes(),
        readiness: ReadinessSnapshot::unknown(),
        user_inputs: policy_user_inputs(paths, &host.id().onion_address()),
        kill: None,
        log,
    })
}

/// The §B.8.7.2 `zxcvbn` inputs: things an attacker would guess first.
fn policy_user_inputs(paths: &Paths, onion: &str) -> Vec<String> {
    let mut inputs = vec!["tornect".to_owned(), onion.to_owned()];
    if let Ok(cfg) = Config::load(&paths.config_file()) {
        inputs.push(cfg.general.device_name);
    }
    if let Ok(user) = std::env::var("USER").or_else(|_| std::env::var("USERNAME")) {
        inputs.push(user);
    }
    inputs
}

/// Pick the route: talk to a running host, or run the guard here.
async fn route(paths: &Paths) -> anyhow::Result<Route> {
    if tornect_platform::ipc::is_running(&paths.state_dir).await {
        Ok(Route::Host)
    } else {
        Ok(Route::Offline(Box::new(offline_context(paths)?)))
    }
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
            Ok(tokio::task::block_in_place(|| dispatch(ctx, req)))
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

/// Read a password from the controlling terminal with echo off (§B.8.7.4:
/// "passwords via TTY prompt, never argv").
///
/// Echo is restored on every exit path, including the error ones — a terminal
/// left with `ECHO` off after a failed prompt is a hostile thing to hand back
/// to someone.
#[cfg(unix)]
fn read_password(prompt: &str) -> anyhow::Result<zeroize::Zeroizing<String>> {
    use std::io::{BufRead as _, Write as _};

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

    let mut line = zeroize::Zeroizing::new(String::new());
    let read = stdin.lock().read_line(&mut line);

    // Restore before looking at the result.
    let restored = termios::tcsetattr(&stdin, OptionalActions::Flush, &original);
    eprintln!();
    restored?;
    read?;

    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    Ok(line)
}

#[cfg(not(unix))]
fn read_password(_prompt: &str) -> anyhow::Result<zeroize::Zeroizing<String>> {
    anyhow::bail!("the password prompt is implemented for Unix at M1 (docs/PLAN.md §B.8.14 M6)")
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
            Ok(_) => {}
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
            let resp = send(paths, &route, IpcOp::On).await?;
            require_ok(&resp)?;
            let payload = resp.payload.as_deref().context("On returned no payload")?;
            let card: MasterOnPayload = tornect_core::unattended::ipc::decode_payload(payload)?;
            println!("Unattended access is ON.");
            println!();
            println!("  EMERGENCY STOP CODE");
            println!("  {}", format_stop_code(&card.stop_code));
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
    let started: RegStartPayload = tornect_core::unattended::ipc::decode_payload(payload)?;

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
fn format_stop_code(code: &[u8; 16]) -> String {
    let hex = data_encoding::HEXLOWER.encode(code);
    hex.as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("-")
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
        let route = route(paths).await?;
        let resp = send(paths, &route, IpcOp::Panic).await?;
        // A panic that could not run must be loud, not swallowed.
        require_ok(&resp)?;
        match resp.detail {
            Some(d) => println!("Sessions ended. {d}"),
            None => println!("Sessions ended."),
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
    use tornect_core::unattended::guard::{AllowAllPaired, AllowAllReAuth, DenyAllReAuth};
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
        let tmp = tempfile::tempdir().unwrap();
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
        let reauth: Arc<dyn tornect_core::unattended::guard::ReAuth> = if reauth_allows {
            Arc::new(AllowAllReAuth::default())
        } else {
            Arc::new(DenyAllReAuth)
        };
        let guard = MutationGuard::new(store, reauth, Arc::new(NoSessionActivity))
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
