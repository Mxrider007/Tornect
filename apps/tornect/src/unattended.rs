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
use tornect_core::levels::FactsSource;
use tornect_core::session_log::{Actor, SessionLog};
use tornect_core::unattended::grant::Preset;
use tornect_core::unattended::guard::{
    ExternalOp, GuardError, MutationGuard, RemoteSessionActivity, SuspendOutcome,
};
use tornect_core::unattended::ipc::{
    GrantOptions, IpcOp, IpcRequest, IpcResponse, LogPage, MasterOnPayload, PolicyInputsPayload,
    RegStartPayload, SetLevelNonePayload, codes, encode_payload,
};
use tornect_core::unattended::readiness::{ReadinessSnapshot, SharedReadiness};
use tornect_core::unattended::store::{GrantStore, LoadMode};
use tornect_core::{Config, Paths};
use tornect_platform::autostart::{self, Autostart, AutostartState, LaunchSpec};
use tornect_platform::ipc::{Endpoint, Reply};
use tornect_signal::fsm::host::KillSwitch;

/// What `IpcOp::Show` calls on a host with a window (§B.1.1): a wake of the
/// window's event loop, which raises the window and arms its cards again. It
/// reaches no sheet.
pub type ShowHook = Arc<dyn Fn() + Send + Sync>;

/// Everything the dispatch needs, whichever route reached it.
pub struct HostContext {
    /// The single enforcement point of §B.8.6.2.
    pub guard: Arc<MutationGuard>,
    /// This host's onion identity key, for `master_on`'s stop token.
    pub host_onion_pk: [u8; 32],
    /// The readiness rows as last probed by the host (at its start and every
    /// 10 min; all `Unknown` on the offline route), shared with the gate.
    /// [`HostContext::readiness_now`] adds the rows read at each request.
    pub readiness: SharedReadiness,
    /// Start at login (§B.8.7.5): `tornect service install|uninstall|status`
    /// and the readiness row `autostart`.
    pub autostart: Arc<dyn Autostart>,
    /// `zxcvbn` inputs for `PolicyInputs` (§B.8.7.2).
    pub user_inputs: Vec<String>,
    /// Ends live handshakes. `None` on the offline route — there are none.
    pub kill: Option<KillSwitch>,
    /// `sessions.log`, for `Log`.
    pub log: SessionLog,
    /// The account facts and the administrator helper task's presence, the
    /// source the guard reads them from (decision M1-67): what `SetLevelNone`'s
    /// answer says still keeps control at the administrator level.
    pub facts: Arc<dyn FactsSource>,
    /// The window host's raise (`IpcOp::Show`, §B.1.1), set by the window
    /// before its control channel starts; `None` on a host without a window,
    /// which refuses `Show`.
    pub show: Option<ShowHook>,
}

impl HostContext {
    /// The readiness report as of now: the static rows plus the probed ones
    /// (`autostart`, read from the OS on every request, so an install or a
    /// removal made outside Tornect shows at once).
    #[must_use]
    pub fn readiness_now(&self) -> ReadinessSnapshot {
        let mut snap = self.readiness.get();
        snap.autostart = autostart::readiness_probe(&self.autostart.status());
        snap.panic_key = panic_key_probe(tornect_platform::hotkey::state());
        snap
    }

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

/// `tornect service install` (`install = Some(elevated)`) or `uninstall`
/// (`None`): §B.8.7.4's `ServiceInstall`/`ServiceUninstall`.
///
/// Order: the backend's preflight first (no dialog for a change that can never
/// be made), then the guard — no remote session for 60 s, a fresh OS
/// re-authentication, the session check again, and the `AutostartChanged{by}`
/// line written *before* the effect, so no change can happen unlogged — then
/// the OS registration. A registration that then fails is answered as a
/// failure and logged as one (`ok: false`), next to the authorised line. No
/// store write (§B.8.7.4).
fn service_change(ctx: &HostContext, id: u64, by: Actor, install: Option<bool>) -> IpcResponse {
    let (op, what) = match install {
        Some(elevated) => (ExternalOp::ServiceInstall { elevated }, "install"),
        None => (ExternalOp::ServiceUninstall, "uninstall"),
    };
    match install {
        Some(elevated) => {
            // Slice-F F2-3: a running host's backend was built when the host
            // started, from its own executable, so through it `install` would
            // register that binary (or a path deleted since), not the
            // `tornect` the user ran. Refused before the dialog.
            if ctx.kill.is_some() {
                return IpcResponse::fail(id, codes::G_PRECONDITION, HOST_ROUTE_INSTALL);
            }
            // r7: the whole-host elevated task is gone (an older command
            // line may still ask for it), refused before any dialog.
            if elevated {
                return IpcResponse::fail(id, codes::G_PRECONDITION, autostart::ELEVATED_TASK_GONE);
            }
            if let Err(e) = ctx.autostart.preflight(elevated) {
                return IpcResponse::fail(id, codes::G_PRECONDITION, e.to_string());
            }
        }
        // Removing nothing changes nothing: no dialog, no log line.
        None => match ctx.autostart.status() {
            Ok(AutostartState::Absent) => {
                let mut r = IpcResponse::ok(id);
                r.detail = Some(describe_autostart(&*ctx.autostart, &AutostartState::Absent));
                return r;
            }
            Ok(AutostartState::Unavailable(why)) => {
                return IpcResponse::fail(
                    id,
                    codes::G_PRECONDITION,
                    format!("start at login is unavailable here: {why}"),
                );
            }
            Ok(AutostartState::Registered(_)) | Err(_) => {}
        },
    }
    if let Err(ref e) = ctx.guard.authorize(by, &op) {
        // Slice-F F2-4: while the keystore cannot be read, a removal is refused
        // too (its line could only be buffered). Say first how to do it by
        // hand: the detail is cut at `MAX_STRING` characters.
        if install.is_none() && matches!(e, GuardError::KeystoreLocked(_)) {
            return IpcResponse::fail(
                id,
                e.code(),
                format!(
                    "the keystore cannot be read, so this removal could not be logged and was \
                     refused; {} ({e})",
                    ctx.autostart.manual_removal()
                ),
            );
        }
        return guard_fail(id, e);
    }
    let done = match install {
        Some(elevated) => ctx.autostart.install(elevated),
        None => ctx.autostart.uninstall(),
    };
    match done {
        Ok(state) => {
            let mut r = IpcResponse::ok(id);
            let mut said = describe_autostart(&*ctx.autostart, &state);
            if install.is_none() && ctx.kill.is_some() {
                said.push_str(HOST_KEEPS_RUNNING);
            }
            r.detail = Some(said);
            r
        }
        Err(e) => {
            let rec = tornect_core::session_log::SessionRecord::at(
                wall_now(),
                tornect_core::session_log::SessionEvent::AutostartChanged,
            )
            .by(by)
            .detail(format!("{what} failed"))
            .ok(false)
            .reason(e.to_string());
            if let Err(log_err) = ctx.guard.store().log_event(&rec) {
                tracing::warn!(error = %log_err, "could not log the failed autostart change");
            }
            IpcResponse::fail(id, codes::G_PRECONDITION, e.to_string())
        }
    }
}

/// Why a running host refuses `service install` (slice-F F2-3; default 2's
/// rule applied to install). Only Linux has a host route today.
const HOST_ROUTE_INSTALL: &str = "a Tornect host is running; stop it (`systemctl --user stop \
     tornect-host`, or Ctrl-C in its terminal) and run `tornect service install` again: it \
     registers the tornect you run";

/// What `service uninstall` through a running host adds (slice-F F2-3).
const HOST_KEEPS_RUNNING: &str = "; the running host keeps running until you stop it \
     (`systemctl --user stop tornect-host`, or Ctrl-C in its terminal)";

/// One line for the operator: what is registered now, and what it runs.
fn describe_autostart(backend: &dyn Autostart, state: &AutostartState) -> String {
    match state {
        // Slice-F F1-1: registered, but whether it starts, and how, is unknown.
        AutostartState::Registered(r) if r.unreadable => format!(
            "{}: {}; {}",
            backend.describe(),
            r.note.as_deref().unwrap_or("this account cannot read it"),
            match (r.enabled, r.elevated) {
                // What `install` just registered: known, though not read back.
                (true, true) => "it starts the host ELEVATED at your next login",
                (true, false) => "it starts at your next login",
                (false, _) => "it may start the host ELEVATED",
            }
        ),
        AutostartState::Registered(r) => {
            let runs = r
                .command
                .as_deref()
                .map(|c| format!(", running {c}"))
                .unwrap_or_default();
            let when = if r.enabled {
                "starts at your next login".to_owned()
            } else {
                format!(
                    "is registered but will not start ({})",
                    r.note.as_deref().unwrap_or("disabled")
                )
            };
            let elevated = if r.elevated { " ELEVATED" } else { "" };
            format!("{}{elevated} {when}{runs}", backend.describe())
        }
        AutostartState::Absent => format!(
            "nothing starts at login ({} is not registered)",
            backend.describe()
        ),
        AutostartState::Unavailable(why) => format!("start at login is unavailable here: {why}"),
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
            let report = guard.store().status_report(ctx.readiness_now());
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

        IpcOp::ServiceInstall { elevated } => service_change(ctx, id, by, Some(elevated)),
        IpcOp::ServiceUninstall => service_change(ctx, id, by, None),

        IpcOp::Readiness => match encode_payload(&ctx.readiness_now()) {
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
            raise,
            generated,
        } => match guard.reg_start(by, &device, raise, generated) {
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
            generated,
        } => {
            let Some(preset) = Preset::from_wire(preset) else {
                return IpcResponse::fail(id, codes::E_BAD_LEN, "unknown preset");
            };
            unit!(guard.reg_finish(by, &device, &reg_txn, &upload, preset, &options, generated))
        }

        // §B.1.1: only a host with a window raises it; the hook wakes the
        // window and reaches no sheet. No mutation: no guard, no dialog, no
        // log line.
        IpcOp::Show => match &ctx.show {
            Some(show) => {
                show();
                IpcResponse::ok(id)
            }
            None => IpcResponse::fail(id, codes::G_UNSUPPORTED, NO_WINDOW_TO_SHOW),
        },
        IpcOp::SetLevelNone { device } => set_level_none(ctx, id, by, &device),

        IpcOp::Unknown(tag) => {
            IpcResponse::fail(id, codes::E_UNKNOWN_KIND, format!("unknown op tag {tag}"))
        }
    }
}

/// Why a host refuses `IpcOp::Show` when it has no window to raise (§B.1.1).
pub(crate) const NO_WINDOW_TO_SHOW: &str = "This Tornect host has no window to show.";

/// The options `set-level <device> none` hands the guard (§B.8.7.4, decision
/// M1-68): the level, and nothing else. Every other field `None` keeps what
/// the grant holds (`GrantOptions`), so a change made meanwhile is never
/// undone and the widening branch of `set_options` is never reached; nothing
/// read from the store fills them, and no input can raise the level.
fn level_none_options() -> GrantOptions {
    GrantOptions {
        elevation: Some(tornect_core::levels::Elevation::None),
        ..GrantOptions::default()
    }
}

/// `IpcOp::SetLevelNone` (§B.8.6.2's deny-direction row; decision M1-68): no
/// re-authentication, and allowed during a remote session. The guard logs
/// `GrantChanged` and, once a lowering is committed, ends that device's
/// sessions at the administrator level (D6); a session below the level goes
/// on. A grant without the level is left as it is, and the answer's detail
/// says so. Every ok answer carries which clause of the turn-off sentence's
/// condition holds now (§B.8.7.1 ⑤a).
fn set_level_none(ctx: &HostContext, id: u64, by: Actor, device: &DeviceId) -> IpcResponse {
    // Read for the answer's wording only: what the guard is sent never
    // depends on it.
    let held = ctx
        .guard
        .store()
        .grant(device)
        .is_some_and(|g| g.holds_level());
    if let Err(ref e) = ctx.guard.set_options(by, device, &level_none_options()) {
        return guard_fail(id, e);
    }
    let payload = SetLevelNonePayload {
        keeps: keeps_at_the_level(ctx, device),
    };
    let mut r = match encode_payload(&payload) {
        Ok(p) => IpcResponse::ok_with(id, p),
        // Never (a one-entry map); the change is committed, so not a failure.
        Err(_) => IpcResponse::ok(id),
    };
    if !held {
        r.detail = Some(LEVEL_ALREADY_NONE.to_owned());
    }
    r
}

/// Which clause of the turn-off sentence's condition holds with `device` at
/// none (§B.8.7.1 ⑤a): another grant holds the level; else the administrator
/// helper task stays registered (a presence that cannot be read counts as
/// registered, decision M1-67); else nothing.
fn keeps_at_the_level(ctx: &HostContext, device: &DeviceId) -> u8 {
    let another = ctx
        .guard
        .store()
        .grants()
        .iter()
        .any(|g| g.device != *device && g.holds_level());
    if another {
        SetLevelNonePayload::ANOTHER_ADMIN_GRANT
    } else if ctx.facts.helper_task().counts() {
        SetLevelNonePayload::HELPER_TASK
    } else {
        SetLevelNonePayload::NOTHING
    }
}

/// The detail of `SetLevelNone`'s answer for a grant without the
/// administrator level.
const LEVEL_ALREADY_NONE: &str = "no administrator access; unchanged";

/// A host context over a fresh store in `home`, for the tests of the window's
/// raise and the second launch: Linux facts, re-authentication allowed, no
/// session, no start at login; `show` is the window's raise, if any.
#[cfg(test)]
pub(crate) fn test_context(home: &std::path::Path, show: Option<ShowHook>) -> HostContext {
    use tornect_core::keystore::FileSecretStore;
    use tornect_core::unattended::clock::SystemClock;
    use tornect_core::unattended::guard::{AllowAllReAuth, NoSessionActivity};
    let paths = Paths::from_home(home);
    paths.ensure().expect("the test's directories");
    let secrets = Arc::new(FileSecretStore::open(paths.keys_dir()).expect("a keystore"));
    let log = SessionLog::new(paths.sessions_log());
    let store = GrantStore::open(
        &paths,
        secrets as Arc<dyn tornect_core::SecretStore>,
        Arc::new(SystemClock::default()),
        log.clone(),
    )
    .expect("a store");
    let facts: Arc<dyn FactsSource> = Arc::new(tornect_core::levels::FixedFacts::linux());
    let guard = MutationGuard::new(
        store,
        Arc::new(AllowAllReAuth::default()),
        Arc::new(NoSessionActivity),
        Arc::clone(&facts),
    );
    HostContext {
        guard: Arc::new(guard),
        host_onion_pk: [0x42; 32],
        readiness: SharedReadiness::default(),
        autostart: Arc::new(autostart::NoAutostart("test".to_owned())),
        user_inputs: Vec::new(),
        kill: None,
        log,
        facts,
        show,
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
        /// Also give it administrator access (Windows: an installed copy, an
        /// administrator account). Its password is generated and printed once,
        /// to a terminal only.
        #[arg(long)]
        administrator: bool,
    },
    /// Change a grant's password.
    SetPassword {
        /// Device ID, fingerprint or pinned label.
        device: String,
        /// Raise it to administrator access, with a new password that is
        /// generated and printed once, to a terminal only.
        #[arg(long)]
        administrator: bool,
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
    /// Take a grant's administrator access away (deny-direction; no
    /// re-authentication, also during a session). Only `none` is accepted.
    SetLevel {
        /// Device ID, fingerprint or pinned label.
        device: String,
        /// The level: `none`.
        #[arg(value_enum)]
        level: LevelArg,
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

/// `set-level`'s level: the command only lowers (decision M1-68).
#[derive(Copy, Clone, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum LevelArg {
    /// No administrator access.
    None,
}

/// `tornect service …` (§B.8.7.5).
#[derive(Subcommand, Debug)]
pub enum ServiceCmd {
    /// Register Tornect to start at login (on Windows also removing an
    /// earlier version's elevated task, through Windows' prompt).
    Install,
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
    #[cfg(windows)]
    {
        Arc::new(tornect_platform::reauth::WindowsReAuth::new())
    }
    #[cfg(not(any(target_os = "linux", windows)))]
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
    let facts: Arc<dyn FactsSource> = Arc::new(tornect_platform::levels::LiveFacts);
    let guard = MutationGuard::new(store, reauth_backend(), activity, Arc::clone(&facts))
        .with_paired_devices(Arc::new(FilePairedDevices::new(
            paths.trusted_devices_file(),
        )))
        .with_attended_history(Arc::new(SessionLogHistory::new(log.clone())))
        .with_server_setup_source(Arc::new(
            tornect_signal::unattended::OpaqueServerSetupSource,
        ));
    // A revoke, disable, suspend or lowering here ends that device's sessions within a
    // second (decision M1-67, D6); the offline route has no sessions to end.
    let guard = match &kill {
        Some(k) => guard.with_device_end(Arc::new(k.clone())),
        None => guard,
    };
    let user_inputs = policy_user_inputs(paths, &host.id().onion_address(), &guard);
    Ok(HostContext {
        guard: Arc::new(guard),
        host_onion_pk: *host.id().public_key_bytes(),
        readiness: SharedReadiness::default(),
        autostart: autostart_backend(paths),
        user_inputs,
        kill,
        log,
        facts,
        show: None,
    })
}

/// What a start-at-login registration for this home runs: this executable's
/// `host` command, with `--home` when the home is not the platform default.
///
/// The executable is the running one (`current_exe`, symlinks resolved on
/// Linux), so whichever `tornect` registers is what starts; a binary deleted
/// or replaced since it started is refused rather than registered by a stale
/// path. A custom home is made absolute: the unit or task starts in another
/// directory.
fn launch_spec(paths: &Paths) -> anyhow::Result<LaunchSpec> {
    let exe = std::env::current_exe().context("finding this executable")?;
    anyhow::ensure!(
        exe.is_file(),
        "{} no longer exists (was it rebuilt or replaced while running?); run          `tornect service install` from the installed binary",
        exe.display()
    );
    let home = if Paths::platform().ok().as_ref() == Some(paths) {
        None
    } else if *paths == Paths::from_home(&paths.config_dir) {
        Some(
            std::fs::canonicalize(&paths.config_dir)
                .with_context(|| format!("resolving {}", paths.config_dir.display()))?,
        )
    } else {
        anyhow::bail!("these Tornect directories are neither the default nor one --home root");
    };
    Ok(LaunchSpec { exe, home })
}

/// The start-at-login backend for this home, or one that says why there is
/// none.
fn autostart_backend(paths: &Paths) -> Arc<dyn Autostart> {
    match launch_spec(paths) {
        Ok(spec) => autostart::for_this_os(spec),
        Err(e) => Arc::new(autostart::NoAutostart(format!("{e:#}"))),
    }
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
    /// A host holds the host lock but nothing answers: its channel failed to
    /// bind (on Windows also when another process made the pipe first, which is
    /// never used). The holder, for messages.
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
            "{}; {}, then run this again",
            unreachable_host(paths, &holder),
            if cfg!(windows) {
                // Default 2 (slice F): every Windows change runs with no host
                // running, the start-at-login one included.
                "if it is the start-at-login host, it runs in its own console window: press \
                 Ctrl-C in that window (or in the terminal of a host you started)"
            } else {
                "stop it (Ctrl-C in its terminal, or `systemctl --user stop tornect-host` for \
                 the start-at-login host)"
            }
        ),
        Probe::NoHost => Ok(Route::Offline(Box::new(offline_context(paths)?))),
    }
}

/// "A host runs here, but nothing answers for it."
fn unreachable_host(paths: &Paths, holder: &str) -> String {
    format!(
        "a Tornect host is running for {} ({holder}), but it has no control channel",
        paths.state_dir.display(),
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
        codes::G_NEEDS_PASSWORD => {
            "\n  On the command line, `tornect unattended set-password <device> --administrator` \
             gives a grant a new generated password, and administrator access with it."
        }
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
pub(crate) fn read_password(prompt: &str) -> anyhow::Result<zeroize::Zeroizing<String>> {
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
pub(crate) fn read_password(_prompt: &str) -> anyhow::Result<zeroize::Zeroizing<String>> {
    anyhow::bail!("the password prompt is implemented for Unix at M1 (docs/PLAN.md §B.8.14 M6)")
}

/// Ask a yes/no question on the terminal (echo on); anything but `y`/`yes` is no.
#[cfg(unix)]
pub(crate) fn confirm(question: &str) -> anyhow::Result<bool> {
    use std::io::Write as _;
    eprint!("{question} [y/N] ");
    std::io::stderr().flush()?;
    let answer = read_line_unbuffered(&std::io::stdin())?;
    Ok(matches!(answer.trim().to_lowercase().as_str(), "y" | "yes"))
}

#[cfg(not(unix))]
pub(crate) fn confirm(_question: &str) -> anyhow::Result<bool> {
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
            administrator,
        } => {
            if waive_attended_check {
                // §B.8.7.4: the waiver is "warned and logged"; the guard logs it.
                eprintln!(
                    "warning: --waive-attended-check skips the rule that this device must \
                     first have had an attended session you watched. The waiver is logged."
                );
            }
            let device = resolve_device(paths, &route, &device).await?;
            if administrator {
                return administrator_form(
                    paths,
                    &route,
                    device,
                    Some((preset.into(), waive_attended_check)),
                    &mut Terminal,
                )
                .await;
            }
            register(
                paths,
                &route,
                device,
                Some(preset.into()),
                waive_attended_check,
            )
            .await
        }
        UnattendedCmd::SetPassword {
            device,
            administrator,
        } => {
            let device = resolve_device(paths, &route, &device).await?;
            if administrator {
                return administrator_form(paths, &route, device, None, &mut Terminal).await;
            }
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
        UnattendedCmd::SetLevel {
            device,
            level: LevelArg::None,
        } => {
            let device = resolve_device(paths, &route, &device).await?;
            set_level_none_cli(paths, &route, device, &mut Terminal).await
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
    register_with(paths, route, device, preset, waive_attended_check, password).await
}

/// [`register`] once `password`, a chosen one, has been read: sent never as
/// generated and never raising (decision M1-67, D4); only
/// [`administrator_form`] does either.
async fn register_with(
    paths: &Paths,
    route: &Route,
    device: DeviceId,
    preset: Option<Preset>,
    waive_attended_check: bool,
    password: zeroize::Zeroizing<String>,
) -> anyhow::Result<()> {
    let (client, reg_request) = tornect_signal::auth::PasswordRegistration::start(&password)
        .map_err(|e| anyhow::anyhow!("starting the registration: {e}"))?;

    let resp = send(
        paths,
        route,
        IpcOp::RegStart {
            device,
            reg_request,
            // The plain forms raise nothing and send a chosen password, never as
            // generated (decision M1-67): only `administrator_form` does either.
            raise: false,
            generated: false,
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
            generated: false,
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

/// What the administrator forms say when standard output is not a terminal
/// (§B.8.7.4): refused before `RegStart`, so nothing is registered.
pub(crate) const GENERATED_OFF_TERMINAL: &str = "A generated password is printed only to a \
     terminal, and standard output is not one, so nothing was registered: run this in a terminal.";

/// The line after a generated password (§B.8.7.4).
pub(crate) const WRITE_IT_DOWN: &str =
    "Write it down now: Tornect does not show it again and keeps no copy.";

/// The ⑤a offer's question on the command line (§B.8.7.4): default yes.
pub(crate) const OFFER_QUESTION: &str = "Give them new passwords now? [Y/n]";

/// The turn-off sentence (§B.8.7.1 ⑤a), printed by `set-level <device> none`;
/// `<device>` stands for the grant's pinned label.
pub(crate) const LEVEL_OFF: &str = "Administrator access is off for <device>. A session of \
     <device> running as administrator ends now.";

/// What the turn-off sentence adds while another grant holds the level.
pub(crate) const LEVEL_OFF_ANOTHER_GRANT: &str = "<device> keeps control of this computer. \
     While another device has administrator access, control can still reach programs that run \
     as administrator. To stop that now, set <device> to View only.";

/// What it adds while the administrator helper task stays registered.
pub(crate) const LEVEL_OFF_HELPER_TASK: &str = "<device> keeps control of this computer. \
     While the administrator helper is still registered: Tornect removes it the next time you \
     sign in here, control can still reach programs that run as administrator. To stop that \
     now, set <device> to View only.";

/// What `set-level <device> none` says of a grant without the level.
pub(crate) const NO_LEVEL_UNCHANGED: &str =
    "<device> has no administrator access; nothing changed.";

/// The terminal as the administrator forms use it: a seam the tests script.
pub(crate) trait Console {
    /// Whether standard output is a terminal: a generated password goes only
    /// there.
    fn stdout_is_terminal(&self) -> bool;
    /// A line on standard output.
    fn out(&mut self, line: &str);
    /// A line on standard error.
    fn err(&mut self, line: &str);
    /// Show `question` on standard error and read one line: `None` at end of
    /// input, on a read error, or when standard input is not a terminal.
    fn ask(&mut self, question: &str) -> Option<String>;
}

/// This process's terminal (every platform: the console's line on Windows).
pub(crate) struct Terminal;

impl Console for Terminal {
    fn stdout_is_terminal(&self) -> bool {
        use std::io::IsTerminal as _;
        std::io::stdout().is_terminal()
    }

    fn out(&mut self, line: &str) {
        crate::host::say(format_args!("{line}"));
    }

    fn err(&mut self, line: &str) {
        crate::host::note(format_args!("{line}"));
    }

    fn ask(&mut self, question: &str) -> Option<String> {
        use std::io::{BufRead as _, IsTerminal as _, Write as _};
        let stdin = std::io::stdin();
        if !stdin.is_terminal() {
            return None;
        }
        eprint!("{question} ");
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        match stdin.lock().read_line(&mut line) {
            Ok(0) | Err(_) => None,
            Ok(_) => Some(line),
        }
    }
}

/// The answer to a default-yes question (§B.8.7.4): Enter, `y` or `yes` is
/// yes; any other answer, end of input, a read error or an input that is not
/// a terminal (`None`) is no.
pub(crate) fn default_yes(answer: Option<&str>) -> bool {
    match answer.map(|a| a.trim().to_lowercase()) {
        None => false,
        Some(a) => a.is_empty() || a == "y" || a == "yes",
    }
}

/// The host's status report.
async fn status_report(
    paths: &Paths,
    route: &Route,
) -> anyhow::Result<tornect_core::unattended::ipc::StatusReport> {
    let resp = send(paths, route, IpcOp::Status).await?;
    require_ok(&resp)?;
    let payload = resp
        .payload
        .as_deref()
        .context("Status returned no payload")?;
    Ok(tornect_core::unattended::ipc::decode_payload(payload)?)
}

/// `device`'s pinned label: its grant's, else its pairing's, else its
/// fingerprint.
fn label_of(
    paths: &Paths,
    report: &tornect_core::unattended::ipc::StatusReport,
    device: &DeviceId,
) -> String {
    if let Some(g) = report.grants.iter().find(|g| g.device == *device) {
        return g.label.clone();
    }
    tornect_signal::pairing::TrustedDeviceStore::open(paths.trusted_devices_file())
        .ok()
        .and_then(|store| {
            store
                .snapshot()
                .devices
                .iter()
                .find(|d| d.device == *device)
                .map(|d| d.label.clone())
        })
        .unwrap_or_else(|| device.fingerprint())
}

/// One registration with a generated password (§B.8.7.4, decision M1-67):
/// `RegStart` declares `generated` and `raise`, the host asks for its
/// re-authentication (with the raising wording for a raise), and `RegFinish`
/// carries `generated` with `options`. The password as it is registered, for
/// the caller to print once: normalized (§B.8.7.2), so a list word's hyphen
/// prints as the space every login reads it as.
async fn generated_registration(
    paths: &Paths,
    route: &Route,
    device: DeviceId,
    preset: Option<Preset>,
    options: GrantOptions,
    raise: bool,
) -> anyhow::Result<zeroize::Zeroizing<String>> {
    let drawn = tornect_core::unattended::password::generate_passphrase()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    // What is registered, and printed, is what a login normalises the typed words
    // to (§B.8.7.2): the list's hyphens read as spaces on both sides.
    let password = tornect_core::unattended::password::normalize(&drawn);
    drop(drawn);
    let (client, reg_request) = tornect_signal::auth::PasswordRegistration::start(&password)
        .map_err(|e| anyhow::anyhow!("starting the registration: {e}"))?;
    let resp = send(
        paths,
        route,
        IpcOp::RegStart {
            device,
            reg_request,
            raise,
            generated: true,
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
    let mut resp = resp;
    if let Some(p) = resp.payload.as_mut() {
        zeroize::Zeroize::zeroize(p);
    }
    let started = started?;
    let host_pk = host_onion_pk(paths)?;
    let ids = tornect_signal::auth::identifiers(device.public_key_bytes(), &host_pk);
    let upload = client
        .finish(&password, &started.reg_response, ids)
        .map_err(|e| anyhow::anyhow!("finishing the registration: {e}"))?;
    let resp = send(
        paths,
        route,
        IpcOp::RegFinish {
            device,
            reg_txn: started.reg_txn,
            upload,
            preset: preset.unwrap_or(Preset::MyMachines).wire(),
            options,
            generated: true,
        },
    )
    .await?;
    require_ok(&resp)?;
    Ok(password)
}

/// The command line's administrator forms (§B.8.7.4, decision M1-67):
/// `grant <device> --administrator` (`create`: the preset and the waiver)
/// creates an admin grant and `set-password <device> --administrator` raises
/// one, each a single guard operation with a generated password, printed once
/// and only to a terminal; then the ⑤a offer to the other Control grants.
///
/// The command line cannot see a grant's level, its mark or clause (ii)
/// (`StatusReport` has none of them; the operator's ruling (b) of
/// 2026-10-02): the offer follows these two forms only, lists every other
/// Control grant without a mark label, and nothing on the command line
/// detects the other changes that make control reach the level (an
/// `enable`, the helper task).
async fn administrator_form(
    paths: &Paths,
    route: &Route,
    device: DeviceId,
    create: Option<(Preset, bool)>,
    io: &mut dyn Console,
) -> anyhow::Result<()> {
    // Refused before `RegStart`, so nothing is registered (§B.8.7.4).
    if !io.stdout_is_terminal() {
        anyhow::bail!("{GENERATED_OFF_TERMINAL}");
    }
    let report = status_report(paths, route).await?;
    let label = label_of(paths, &report, &device);
    // ⑤a's warning first (§B.8.7.1, §B.8.7.4; the operator's rulings of
    // 2026-10-02): before an admin grant is created, since until the wizard's
    // step exists this is the only way to create one, and before a grant is
    // raised, which gives it the same access.
    io.err(&tornect_core::levels::ADMINISTRATOR_WARNING.replace("<device>", &label));
    // The other Control grants, as they were before this change.
    let control = tornect_core::session_log::SessionMode::Control.wire();
    let others: Vec<(DeviceId, String)> = report
        .grants
        .iter()
        .filter(|g| g.device != device && g.mode == control)
        .map(|g| (g.device, g.label.clone()))
        .collect();
    let options = GrantOptions {
        elevation: Some(tornect_core::levels::Elevation::Admin),
        waive_attended_precondition: create.is_some_and(|(_, waive)| waive),
        ..GrantOptions::default()
    };
    let shown = generated_registration(
        paths,
        route,
        device,
        create.map(|(preset, _)| preset),
        options,
        true,
    )
    .await?;
    io.out(&format!("New password for \"{label}\": {}", shown.as_str()));
    io.out(WRITE_IT_DOWN);
    drop(shown);
    offer_new_passwords(paths, route, others, io).await
}

/// The ⑤a offer (§B.8.7.1, §B.8.7.4): the other Control grants by their pinned
/// labels under ⑤a's heading, then the default-yes question, then one
/// *Change password* each, with a generated password printed once. A
/// registration that does not finish (its re-authentication cancelled, say)
/// keeps that device's old password: the list is shown again with the devices
/// that still have it, and asked again.
async fn offer_new_passwords(
    paths: &Paths,
    route: &Route,
    mut remaining: Vec<(DeviceId, String)>,
    io: &mut dyn Console,
) -> anyhow::Result<()> {
    let mut first = true;
    while !remaining.is_empty() {
        let labels = remaining
            .iter()
            .map(|(_, label)| format!("\"{label}\""))
            .collect::<Vec<_>>()
            .join(", ");
        if first {
            io.err(&format!(
                "These devices have control of this computer: {labels}. From now on their \
                 control can reach programs that run as administrator here."
            ));
        } else {
            io.err(&format!(
                "These devices still have their old password: {labels}."
            ));
        }
        first = false;
        if !default_yes(io.ask(OFFER_QUESTION).as_deref()) {
            io.err("Their passwords were not changed.");
            return Ok(());
        }
        let mut left = Vec::new();
        for (device, label) in remaining {
            match generated_registration(paths, route, device, None, GrantOptions::default(), false)
                .await
            {
                Ok(shown) => {
                    io.out(&format!("New password for \"{label}\": {}", shown.as_str()));
                    io.out(WRITE_IT_DOWN);
                }
                Err(e) => {
                    io.err(&format!("\"{label}\" keeps its old password: {e:#}"));
                    left.push((device, label));
                }
            }
        }
        remaining = left;
    }
    Ok(())
}

/// `tornect unattended set-level <device> none` (§B.8.7.4, decision M1-68):
/// one `SetLevelNone`, then the turn-off sentence with its condition (§B.8.7.1
/// ⑤a), or the line that the grant had no administrator level.
async fn set_level_none_cli(
    paths: &Paths,
    route: &Route,
    device: DeviceId,
    io: &mut dyn Console,
) -> anyhow::Result<()> {
    let report = status_report(paths, route).await?;
    let label = label_of(paths, &report, &device);
    let resp = send(paths, route, IpcOp::SetLevelNone { device }).await?;
    require_ok(&resp)?;
    if resp.detail.as_deref() == Some(LEVEL_ALREADY_NONE) {
        io.out(&NO_LEVEL_UNCHANGED.replace("<device>", &label));
        return Ok(());
    }
    io.out(&LEVEL_OFF.replace("<device>", &label));
    let payload = resp
        .payload
        .as_deref()
        .context("SetLevelNone returned no payload")?;
    let payload: SetLevelNonePayload = tornect_core::unattended::ipc::decode_payload(payload)?;
    payload.validate()?;
    let condition = match payload.keeps {
        SetLevelNonePayload::ANOTHER_ADMIN_GRANT => Some(LEVEL_OFF_ANOTHER_GRANT),
        SetLevelNonePayload::HELPER_TASK => Some(LEVEL_OFF_HELPER_TASK),
        _ => None,
    };
    if let Some(line) = condition {
        io.out(&line.replace("<device>", &label));
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
    use tornect_core::unattended::readiness::{Probe, row_title};
    println!(
        "Readiness (a row this computer cannot read yet is unknown: it never refuses a session, \
         and it raises the badge)"
    );
    for (name, probe) in snap.fields() {
        let title = row_title(name);
        let line = match (name, probe) {
            // §B.8.7.4: "Panic key: bound / unavailable".
            ("panic_key", Probe::Ok) => format!("{title}: bound"),
            ("panic_key", Probe::Fail(_) | Probe::Unknown) => format!("{title}: unavailable"),
            (_, Probe::Ok) => format!("{title}: ok"),
            (_, Probe::Warn(m)) => format!("{title}: warning: {m}"),
            (_, Probe::Fail(m)) => format!("{title}: FAIL: {m}"),
            (_, Probe::Unknown) => format!("{title}: unknown"),
        };
        println!("  {line}");
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

/// The readiness row of the panic key (§B.8.7.4, "Panic key: bound /
/// unavailable"): ok where this process watches it; otherwise a red row (a
/// badge, never `HOST_NOT_READY`, §B.8.14). A process that is no host never
/// binds it.
fn panic_key_probe(
    state: tornect_platform::hotkey::KeyState,
) -> tornect_core::unattended::readiness::Probe {
    use tornect_core::unattended::readiness::Probe as Row;
    use tornect_platform::hotkey::KeyState;
    match state {
        KeyState::Bound => Row::Ok,
        KeyState::NotTried | KeyState::Unavailable => Row::Fail(state.row().to_owned()),
    }
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

/// What every start-at-login message ends with (§B.8.7.5): Tornect never
/// configures auto-login, so the host starts only once someone logs in.
const AFTER_LOGIN_ONLY: &str = "The host starts only after you log in: Tornect never turns on \
     automatic login, so after a reboot this computer stays unreachable until someone logs in.";

/// What the Linux start-at-login host serves (slice-F F2-1): the systemd user
/// unit gives it no terminal and it has no window, so it can show no session
/// (`crate::host::HostWiring::without_unattended`). Windows' task runs it in a
/// console window, which is its terminal.
const LOGIN_HOST_PINGS_ONLY: &str = "Started at login, the host answers pings only and refuses \
     every session, because it has no window or terminal to show one.";

/// `tornect service install|uninstall|status`
///
/// `install` and `uninstall` change what starts at login, which is
/// access-increasing (§B.8.6.2): they go through the running host, or the
/// guard offline, like every other mutation, and the host or this command
/// asks for the OS password. `status` only reads the registration, here.
pub fn service(paths: &Paths, cmd: ServiceCmd) -> anyhow::Result<()> {
    let op = match cmd {
        ServiceCmd::Install => IpcOp::ServiceInstall { elevated: false },
        ServiceCmd::Uninstall => IpcOp::ServiceUninstall,
        ServiceCmd::Status => return service_status(paths),
    };
    let installing = matches!(op, IpcOp::ServiceInstall { .. });
    runtime()?.block_on(async move {
        let route = route(paths).await?;
        let resp = send(paths, &route, op).await?;
        require_ok(&resp)?;
        if let Some(d) = &resp.detail {
            println!("{d}.");
        }
        if installing {
            if cfg!(target_os = "linux") {
                println!("{LOGIN_HOST_PINGS_ONLY}");
            }
            println!("{AFTER_LOGIN_ONLY}");
        }
        Ok(())
    })
}

/// `tornect service status`: the registration as the OS reports it, and the
/// readiness row it produces.
fn service_status(paths: &Paths) -> anyhow::Result<()> {
    use tornect_core::unattended::readiness::Probe;
    let backend = autostart_backend(paths);
    let status = backend.status();
    match &status {
        Ok(state) => println!("{}.", describe_autostart(&*backend, state)),
        Err(e) => println!("Could not read {}: {e}", backend.describe()),
    }
    let row = match autostart::readiness_probe(&status) {
        Probe::Ok => "ok".to_owned(),
        Probe::Warn(m) => format!("warn: {m}"),
        Probe::Fail(m) => format!("FAIL: {m}"),
        Probe::Unknown => "unknown".to_owned(),
    };
    println!("Readiness row `autostart`: {row}");
    if cfg!(target_os = "linux") {
        println!("{LOGIN_HOST_PINGS_ONLY}");
    }
    println!("{AFTER_LOGIN_ONLY}");
    Ok(())
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
        AllowAllPaired, AllowAllReAuth, DenyAllReAuth, DeviceSessionEnd, EndScope,
        NoSessionActivity, ScriptedActivity,
    };
    use tornect_core::unattended::ipc::{StatusReport, decode_payload};

    use super::*;

    const HOST_PK: [u8; 32] = [0x42; 32];

    struct Env {
        _tmp: tempfile::TempDir,
        ctx: HostContext,
        autostart: Arc<FakeAutostart>,
    }

    /// A start-at-login backend that records what it was asked and answers
    /// as scripted.
    #[derive(Default)]
    struct FakeAutostart {
        installs: std::sync::Mutex<Vec<bool>>,
        uninstalls: std::sync::atomic::AtomicUsize,
        state: std::sync::Mutex<Option<AutostartState>>,
        /// `Some`: `preflight` refuses with this reason.
        refuse: Option<String>,
        /// `Some`: `install`/`uninstall` fail with this reason after preflight.
        fail: Option<String>,
        /// `Some`: `status` fails with this reason.
        unreadable_status: Option<String>,
    }

    impl FakeAutostart {
        fn installs(&self) -> Vec<bool> {
            self.installs.lock().unwrap().clone()
        }

        fn uninstalls(&self) -> usize {
            self.uninstalls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl Autostart for FakeAutostart {
        fn preflight(&self, _elevated: bool) -> Result<(), autostart::AutostartError> {
            match &self.refuse {
                Some(why) => Err(autostart::AutostartError::Unavailable(why.clone())),
                None => Ok(()),
            }
        }

        fn install(&self, elevated: bool) -> Result<AutostartState, autostart::AutostartError> {
            self.preflight(elevated)?;
            self.installs.lock().unwrap().push(elevated);
            if let Some(why) = &self.fail {
                return Err(autostart::AutostartError::Failed(why.clone()));
            }
            let state = AutostartState::Registered(autostart::Registration {
                enabled: true,
                elevated,
                command: Some("\"/opt/tornect\" \"host\"".to_owned()),
                note: None,
                unreadable: false,
            });
            *self.state.lock().unwrap() = Some(state.clone());
            Ok(state)
        }

        fn uninstall(&self) -> Result<AutostartState, autostart::AutostartError> {
            self.uninstalls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if let Some(why) = &self.fail {
                return Err(autostart::AutostartError::Failed(why.clone()));
            }
            *self.state.lock().unwrap() = None;
            Ok(AutostartState::Absent)
        }

        fn status(&self) -> Result<AutostartState, autostart::AutostartError> {
            if let Some(why) = &self.unreadable_status {
                return Err(autostart::AutostartError::Failed(why.clone()));
            }
            Ok(self
                .state
                .lock()
                .unwrap()
                .clone()
                .unwrap_or(AutostartState::Absent))
        }

        fn describe(&self) -> String {
            "the test's start-at-login backend".to_owned()
        }

        fn manual_removal(&self) -> String {
            "remove it by hand as the test says".to_owned()
        }
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
        env_with_autostart(tmp, reauth, activity, FakeAutostart::default())
    }

    /// [`env_with`] with a scripted start-at-login backend.
    fn env_with_autostart(
        tmp: tempfile::TempDir,
        reauth: Arc<dyn tornect_core::unattended::guard::ReAuth>,
        activity: Arc<dyn RemoteSessionActivity>,
        autostart: FakeAutostart,
    ) -> Env {
        let autostart = Arc::new(autostart);
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
        let guard = MutationGuard::new(
            store,
            reauth,
            activity,
            Arc::new(tornect_core::levels::FixedFacts::linux()),
        )
        .with_paired_devices(Arc::new(AllowAllPaired))
        .with_server_setup_source(Arc::new(
            tornect_signal::unattended::OpaqueServerSetupSource,
        ));
        Env {
            _tmp: tmp,
            ctx: HostContext {
                guard: Arc::new(guard),
                host_onion_pk: HOST_PK,
                readiness: SharedReadiness::default(),
                autostart: Arc::clone(&autostart) as Arc<dyn Autostart>,
                user_inputs: vec!["tornect".to_owned()],
                kill: None,
                log,
                facts: Arc::new(tornect_core::levels::FixedFacts::linux()),
                show: None,
            },
            autostart,
        }
    }

    fn go(ctx: &HostContext, op: IpcOp) -> IpcResponse {
        dispatch(ctx, IpcRequest { id: 1, op })
    }

    /// r7 (the operator's ruling of 2026-09-28): the whole-host elevated
    /// task is gone; a request for it (an older command line) is refused
    /// before any dialog, saying why, and nothing is registered or logged.
    #[test]
    fn the_elevated_install_is_refused_and_says_why() {
        let reauth = Arc::new(AllowAllReAuth::default());
        let env = env_with_autostart(
            tempfile::tempdir().unwrap(),
            Arc::clone(&reauth) as Arc<dyn tornect_core::unattended::guard::ReAuth>,
            Arc::new(NoSessionActivity),
            FakeAutostart::default(),
        );
        let resp = go(&env.ctx, IpcOp::ServiceInstall { elevated: true });
        assert!(!resp.ok);
        assert_eq!(resp.code, codes::G_PRECONDITION);
        assert_eq!(resp.detail.as_deref(), Some(autostart::ELEVATED_TASK_GONE));
        assert!(env.autostart.installs().is_empty());
        assert!(reauth.calls().is_empty(), "no dialog");
        assert!(autostart_lines(&env.ctx).is_empty());
    }

    /// Slice-F F2-1: what `service install` says on Linux about the host it
    /// registers is what the release README says.
    #[test]
    fn the_login_host_line_is_the_readmes() {
        let readme = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../packaging/release/README-release.md"
        ))
        .unwrap();
        let readme = readme.split_whitespace().collect::<Vec<_>>().join(" ");
        let said = LOGIN_HOST_PINGS_ONLY
            .strip_prefix("Started at login, ")
            .and_then(|s| s.strip_suffix('.'))
            .unwrap();
        assert!(readme.contains(said), "the README does not say: {said}");
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
                raise: false,
                generated: false,
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
                generated: false,
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
        let Env { _tmp, ctx, .. } = env(true);
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
            ..
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
            ..
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
            Arc::new(tornect_core::levels::FixedFacts::linux()),
        );
        let ctx = HostContext {
            guard: Arc::new(deny),
            host_onion_pk: HOST_PK,
            readiness: SharedReadiness::default(),
            autostart: Arc::new(autostart::NoAutostart("test".to_owned())),
            user_inputs: Vec::new(),
            kill: None,
            log: allow.ctx.log.clone(),
            facts: Arc::new(tornect_core::levels::FixedFacts::linux()),
            show: None,
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

    /// §B.1.1, §B.8.7.4: a host with no window to raise (the terminal host, the
    /// headless one) refuses `Show` with the reason. It is no mutation: no
    /// dialog is asked and nothing is logged.
    #[test]
    fn a_host_without_a_window_refuses_show() {
        let reauth = Arc::new(AllowAllReAuth::default());
        let env = env_with(
            tempfile::tempdir().unwrap(),
            Arc::clone(&reauth) as Arc<dyn tornect_core::unattended::guard::ReAuth>,
            Arc::new(NoSessionActivity),
        );
        let before = env.ctx.log.read_all().unwrap().len();
        let resp = go(&env.ctx, IpcOp::Show);
        assert!(!resp.ok);
        assert_eq!(resp.code, codes::G_UNSUPPORTED);
        assert_eq!(resp.detail.as_deref(), Some(NO_WINDOW_TO_SHOW));
        assert!(reauth.calls().is_empty(), "no dialog");
        assert_eq!(
            env.ctx.log.read_all().unwrap().len(),
            before,
            "nothing logged"
        );
    }

    /// M1-46 (kept): a host that started without its store answers `tornect
    /// panic` only; `Show` is refused with that reason, and nothing ends.
    #[test]
    fn the_storeless_host_refuses_show() {
        let kill = KillSwitch::new();
        let resp = dispatch_without_store(
            &kill,
            "the store is locked",
            IpcRequest {
                id: 5,
                op: IpcOp::Show,
            },
        );
        assert!(!resp.ok);
        assert_eq!(resp.code, codes::G_PRECONDITION);
        assert!(
            resp.detail
                .as_deref()
                .is_some_and(|d| d.contains("answers only `tornect panic`")),
            "{resp:?}"
        );
        assert_eq!(kill.fired(), None);
    }

    /// The operations §B.8.14 schedules for later report that plainly instead of
    /// returning `ok` for something that did not happen — but they still run the
    /// guard's authorisation and log line first.
    #[test]
    fn deferred_operations_say_so_rather_than_faking_success() {
        let env = env(true);
        for op in [
            IpcOp::BackupExport {
                path: "/tmp/x".to_owned(),
            },
            IpcOp::BackupImport {
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
                generated: false,
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
                raise: false,
                generated: false,
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
                generated: false,
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

    // ------------------------------------------------------ start at login

    /// The `AutostartChanged` lines in `sessions.log`, as (by, detail, ok).
    fn autostart_lines(ctx: &HostContext) -> Vec<(Option<Actor>, Option<String>, Option<bool>)> {
        ctx.log
            .read_all()
            .unwrap()
            .into_iter()
            .filter(|r| r.event == tornect_core::session_log::SessionEvent::AutostartChanged)
            .map(|r| (r.by, r.detail, r.ok))
            .collect()
    }

    fn refused_lines(ctx: &HostContext, op: &str) -> usize {
        ctx.log
            .read_all()
            .unwrap()
            .into_iter()
            .filter(|r| {
                r.event == tornect_core::session_log::SessionEvent::GrantMutationRefused
                    && r.op.as_deref() == Some(op)
            })
            .count()
    }

    /// §B.8.6.2: changing what starts at login is access-increasing. Without
    /// re-authentication nothing is registered, and the refusal is logged.
    #[test]
    fn service_install_is_refused_without_reauth() {
        let env = env(false);
        // Something to remove, so `uninstall` has a change to refuse.
        *env.autostart.state.lock().unwrap() =
            Some(AutostartState::Registered(autostart::Registration {
                enabled: true,
                ..autostart::Registration::default()
            }));
        for (op, name) in [
            (IpcOp::ServiceInstall { elevated: false }, "service_install"),
            (IpcOp::ServiceUninstall, "service_uninstall"),
        ] {
            let resp = go(&env.ctx, op);
            assert!(!resp.ok, "{name} went through without re-authentication");
            assert_eq!(resp.code, codes::G_REAUTH_FAILED, "{:?}", resp.detail);
        }
        assert!(
            env.autostart.installs().is_empty(),
            "nothing was registered"
        );
        assert_eq!(env.autostart.uninstalls(), 0, "nothing was removed");
        assert!(autostart_lines(&env.ctx).is_empty());
        assert_eq!(refused_lines(&env.ctx, "service_install"), 1);
        assert_eq!(refused_lines(&env.ctx, "service_uninstall"), 1);
    }

    /// Slice-F F2-3: through a running host, `service install` registered
    /// the host's own executable, fixed when that host started, not the
    /// `tornect` the user ran. The host route refuses it before the dialog;
    /// `uninstall` still goes through the host, whose answer says that the
    /// host keeps running.
    #[test]
    fn a_running_host_refuses_service_install_but_uninstalls() {
        let reauth = Arc::new(AllowAllReAuth::default());
        let mut env = env_with_autostart(
            tempfile::tempdir().unwrap(),
            Arc::clone(&reauth) as Arc<dyn tornect_core::unattended::guard::ReAuth>,
            Arc::new(NoSessionActivity),
            FakeAutostart::default(),
        );
        env.ctx.kill = Some(KillSwitch::new());
        for elevated in [false, true] {
            let resp = go(&env.ctx, IpcOp::ServiceInstall { elevated });
            assert!(!resp.ok, "the host route installed (elevated: {elevated})");
            assert_eq!(resp.code, codes::G_PRECONDITION, "{:?}", resp.detail);
            let said = resp.detail.unwrap_or_default();
            assert!(said.contains("registers the tornect you run"), "{said}");
            assert!(
                said.contains("systemctl --user stop tornect-host"),
                "{said}"
            );
        }
        assert!(env.autostart.installs().is_empty(), "the backend ran");
        assert!(reauth.calls().is_empty(), "a dialog: {:?}", reauth.calls());
        assert!(autostart_lines(&env.ctx).is_empty());

        *env.autostart.state.lock().unwrap() =
            Some(AutostartState::Registered(autostart::Registration {
                enabled: true,
                ..autostart::Registration::default()
            }));
        let resp = go(&env.ctx, IpcOp::ServiceUninstall);
        assert!(resp.ok, "{:?}", resp.detail);
        assert_eq!(env.autostart.uninstalls(), 1);
        let said = resp.detail.unwrap_or_default();
        assert!(said.contains("keeps running until you stop it"), "{said}");
    }

    /// Slice-F F2-4's side effect: while the keystore cannot be read, `service
    /// uninstall` is refused as well (its line could only be buffered), and
    /// the refusal says how to remove the registration by hand.
    ///
    /// The unreadable keystore is a real key file set to mode 000, which does
    /// not stop root: run as root (a container build, say), this test checks
    /// nothing and returns at once (review P2-I3).
    #[cfg(unix)]
    #[test]
    fn an_uninstall_the_keystore_refuses_names_the_manual_removal() {
        use std::os::unix::fs::PermissionsExt as _;
        if rustix::process::geteuid().is_root() {
            return;
        }
        let registered = || FakeAutostart {
            state: std::sync::Mutex::new(Some(AutostartState::Registered(
                autostart::Registration {
                    enabled: true,
                    ..autostart::Registration::default()
                },
            ))),
            ..FakeAutostart::default()
        };
        // Unattended access turned on once: the master key exists.
        let env = env_with_autostart(
            tempfile::tempdir().unwrap(),
            Arc::new(AllowAllReAuth::default()),
            Arc::new(NoSessionActivity),
            registered(),
        );
        assert!(go(&env.ctx, IpcOp::On).ok);
        let Env { _tmp: tmp, ctx, .. } = env;
        drop(ctx);
        // Now the keystore cannot be read.
        let key = Paths::from_home(tmp.path()).keys_dir().join(format!(
            "{}.secret",
            tornect_core::unattended::codec::MASTER_KEY_ENTRY
        ));
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o000)).unwrap();
        let env = env_with_autostart(
            tmp,
            Arc::new(AllowAllReAuth::default()),
            Arc::new(NoSessionActivity),
            registered(),
        );
        let resp = go(&env.ctx, IpcOp::ServiceUninstall);
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(!resp.ok, "removed while the keystore was unreadable");
        assert_eq!(resp.code, codes::G_KEYSTORE_LOCKED, "{:?}", resp.detail);
        let said = resp.detail.unwrap_or_default();
        assert!(
            said.contains("remove it by hand as the test says"),
            "{said}"
        );
        assert_eq!(env.autostart.uninstalls(), 0);
    }

    /// With re-authentication the backend runs, the change is logged as
    /// `AutostartChanged{by: cli}` (§B.8.7.4), and the answer says what now
    /// starts at login.
    #[test]
    fn service_install_and_uninstall_run_and_are_logged_with_reauth() {
        let env = env(true);
        let resp = go(&env.ctx, IpcOp::ServiceInstall { elevated: false });
        assert!(resp.ok, "{:?}", resp.detail);
        assert_eq!(env.autostart.installs(), vec![false]);
        let said = resp.detail.unwrap_or_default();
        assert!(said.contains("/opt/tornect"), "{said}");

        let resp = go(&env.ctx, IpcOp::ServiceUninstall);
        assert!(resp.ok, "{:?}", resp.detail);
        assert_eq!(env.autostart.uninstalls(), 1);

        let lines = autostart_lines(&env.ctx);
        let details: Vec<&str> = lines
            .iter()
            .map(|(_, d, _)| d.as_deref().unwrap_or(""))
            .collect();
        assert_eq!(details, ["install", "uninstall"], "{lines:?}");
        assert!(
            lines.iter().all(|(by, _, _)| *by == Some(Actor::Cli)),
            "{lines:?}"
        );
        assert!(
            lines.iter().all(|(_, _, ok)| *ok != Some(false)),
            "{lines:?}"
        );
    }

    /// Removing a registration that does not exist changes nothing, so it
    /// needs no dialog and writes no log line.
    #[test]
    fn uninstalling_nothing_needs_no_dialog() {
        let reauth = Arc::new(AllowAllReAuth::default());
        let env = env_with_autostart(
            tempfile::tempdir().unwrap(),
            Arc::clone(&reauth) as Arc<dyn tornect_core::unattended::guard::ReAuth>,
            Arc::new(NoSessionActivity),
            FakeAutostart::default(),
        );
        let resp = go(&env.ctx, IpcOp::ServiceUninstall);
        assert!(resp.ok, "{:?}", resp.detail);
        assert!(
            resp.detail
                .unwrap_or_default()
                .contains("nothing starts at login")
        );
        assert!(reauth.calls().is_empty());
        assert_eq!(env.autostart.uninstalls(), 0);
        assert!(autostart_lines(&env.ctx).is_empty());
    }

    /// Slice-F F1-1, a regression guard: a registration whose state cannot be
    /// read, or that exists but this account cannot read, is not "nothing to
    /// remove": `uninstall` re-authenticates, is logged, and reaches the
    /// backend (which decides how to delete and whether it is gone).
    #[test]
    fn uninstalling_an_unreadable_registration_goes_through_the_guard() {
        for fake in [
            FakeAutostart {
                unreadable_status: Some("could not read the start-at-login task".to_owned()),
                ..FakeAutostart::default()
            },
            FakeAutostart {
                state: std::sync::Mutex::new(Some(AutostartState::Registered(
                    autostart::Registration {
                        note: Some("a task \\Tornect exists that this account cannot read".into()),
                        unreadable: true,
                        ..autostart::Registration::default()
                    },
                ))),
                ..FakeAutostart::default()
            },
        ] {
            let reauth = Arc::new(AllowAllReAuth::default());
            let env = env_with_autostart(
                tempfile::tempdir().unwrap(),
                Arc::clone(&reauth) as Arc<dyn tornect_core::unattended::guard::ReAuth>,
                Arc::new(NoSessionActivity),
                fake,
            );
            let resp = go(&env.ctx, IpcOp::ServiceUninstall);
            assert!(resp.ok, "{:?}", resp.detail);
            assert_eq!(reauth.calls(), vec!["service_uninstall".to_owned()]);
            assert_eq!(env.autostart.uninstalls(), 1);
            assert_eq!(
                autostart_lines(&env.ctx),
                vec![(Some(Actor::Cli), Some("uninstall".to_owned()), None)]
            );
        }
    }

    /// SLICE-D D1 still holds for autostart: a host that starts while the
    /// offline command's dialog is open stops the change.
    #[test]
    fn a_host_that_starts_during_the_dialog_stops_an_offline_service_install() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        let reauth = Arc::new(HostStartsDuringDialog::new(&paths, 0));
        let env = env_with_autostart(
            tmp,
            reauth,
            offline_activity(&paths),
            FakeAutostart::default(),
        );
        let resp = go(&env.ctx, IpcOp::ServiceInstall { elevated: false });
        assert!(
            !resp.ok,
            "registered beside a host that started during the dialog"
        );
        assert_eq!(
            resp.code,
            codes::G_REMOTE_SESSION_ACTIVE,
            "{:?}",
            resp.detail
        );
        assert!(env.autostart.installs().is_empty());
        assert!(autostart_lines(&env.ctx).is_empty());
    }

    /// As the CLI runs it: the offline route picked before a host took its
    /// lock refuses the install and blames the host.
    #[test]
    fn the_offline_route_refuses_service_install_beside_a_host_that_started() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        let rt = runtime().unwrap();
        let picked = rt.block_on(route(&paths)).unwrap();
        assert!(matches!(picked, Route::Offline(_)));
        let host = crate::host::HostLock::acquire(&paths).unwrap();
        let said = rt
            .block_on(send(
                &paths,
                &picked,
                IpcOp::ServiceInstall { elevated: false },
            ))
            .unwrap_err()
            .to_string();
        assert!(said.contains("while this command ran"), "{said}");
        drop(host);
    }

    /// A change that can never be made is refused before the dialog: nobody
    /// types a password for it, and nothing is logged as changed.
    #[test]
    fn an_impossible_install_is_refused_before_the_dialog() {
        let reauth = Arc::new(AllowAllReAuth::default());
        let env = env_with_autostart(
            tempfile::tempdir().unwrap(),
            Arc::clone(&reauth) as Arc<dyn tornect_core::unattended::guard::ReAuth>,
            Arc::new(NoSessionActivity),
            FakeAutostart {
                refuse: Some("no systemd user manager answers".to_owned()),
                ..FakeAutostart::default()
            },
        );
        let resp = go(&env.ctx, IpcOp::ServiceInstall { elevated: false });
        assert!(!resp.ok);
        assert_eq!(resp.code, codes::G_PRECONDITION, "{:?}", resp.detail);
        assert!(
            resp.detail
                .unwrap_or_default()
                .contains("no systemd user manager")
        );
        assert!(
            reauth.calls().is_empty(),
            "no dialog for an impossible change"
        );
        assert!(autostart_lines(&env.ctx).is_empty());
    }

    /// When the OS refuses after the dialog, the answer says so and the log
    /// records the failed change next to the authorised one.
    #[test]
    fn a_failed_install_is_reported_and_logged() {
        let env = env_with_autostart(
            tempfile::tempdir().unwrap(),
            Arc::new(AllowAllReAuth::default()),
            Arc::new(NoSessionActivity),
            FakeAutostart {
                fail: Some("schtasks.exe failed: ERROR: Access is denied.".to_owned()),
                ..FakeAutostart::default()
            },
        );
        let resp = go(&env.ctx, IpcOp::ServiceInstall { elevated: false });
        assert!(!resp.ok, "a failed registration must not report success");
        assert_eq!(resp.code, codes::G_PRECONDITION, "{:?}", resp.detail);
        assert!(resp.detail.unwrap_or_default().contains("Access is denied"));
        let lines = autostart_lines(&env.ctx);
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert_eq!(lines[1].2, Some(false), "the failure is logged: {lines:?}");
    }

    /// The readiness row `autostart` is the backend's answer, on `Readiness`
    /// and inside `Status`, read at request time.
    #[test]
    fn the_readiness_autostart_row_follows_the_backend() {
        use tornect_core::unattended::readiness::Probe;
        let env = env(true);
        let read = |ctx: &HostContext| {
            let resp = go(ctx, IpcOp::Readiness);
            let snap: ReadinessSnapshot = decode_payload(resp.payload.as_deref().unwrap()).unwrap();
            snap.autostart
        };
        assert!(matches!(read(&env.ctx), Probe::Warn(m) if m.contains("not registered")));
        assert!(go(&env.ctx, IpcOp::ServiceInstall { elevated: false }).ok);
        assert_eq!(read(&env.ctx), Probe::Ok);
        let resp = go(&env.ctx, IpcOp::Status);
        let report: StatusReport = decode_payload(resp.payload.as_deref().unwrap()).unwrap();
        assert_eq!(report.readiness.autostart, Probe::Ok);
        assert!(!go(&env.ctx, IpcOp::ServiceInstall { elevated: true }).ok);
        assert_eq!(
            read(&env.ctx),
            Probe::Ok,
            "the refused elevated task changed nothing"
        );
    }

    /// The registration runs this executable's host for this home: the default
    /// home needs no `--home`, a `--home` root is passed absolute.
    #[test]
    fn the_launch_spec_names_this_executable_and_home() {
        let tmp = tempfile::tempdir().unwrap();
        let custom = Paths::from_home(tmp.path());
        custom.ensure().unwrap();
        let spec = launch_spec(&custom).unwrap();
        assert_eq!(spec.exe, std::env::current_exe().unwrap());
        assert_eq!(spec.home, Some(std::fs::canonicalize(tmp.path()).unwrap()));
        if let Ok(default) = Paths::platform() {
            assert_eq!(launch_spec(&default).unwrap().home, None);
        }
    }

    // ------------------------------------------- the administrator forms (M1-67)

    /// The terminal of a test: answers scripted, every line kept.
    struct Script {
        terminal: bool,
        answers: std::collections::VecDeque<Option<String>>,
        out: Vec<String>,
        err: Vec<String>,
        asked: Vec<String>,
    }

    impl Script {
        fn new(terminal: bool, answers: &[Option<&str>]) -> Self {
            Self {
                terminal,
                answers: answers.iter().map(|a| a.map(str::to_owned)).collect(),
                out: Vec::new(),
                err: Vec::new(),
                asked: Vec::new(),
            }
        }
    }

    impl Console for Script {
        fn stdout_is_terminal(&self) -> bool {
            self.terminal
        }
        fn out(&mut self, line: &str) {
            self.out.push(line.to_owned());
        }
        fn err(&mut self, line: &str) {
            self.err.push(line.to_owned());
        }
        fn ask(&mut self, question: &str) -> Option<String> {
            self.asked.push(question.to_owned());
            self.answers.pop_front().flatten()
        }
    }

    /// Re-authentication that records every dialog and refuses the `refuse`-th
    /// plain `reg_start` (1-based): a prompt the person cancelled.
    struct CancelOne {
        calls: std::sync::Mutex<Vec<String>>,
        refuse: usize,
    }

    impl tornect_core::unattended::guard::ReAuth for CancelOne {
        fn reauthenticate(
            &self,
            op: &str,
        ) -> Result<(), tornect_core::unattended::guard::ReAuthError> {
            let mut calls = self.calls.lock().unwrap();
            calls.push(op.to_owned());
            let plain = calls.iter().filter(|c| c.as_str() == "reg_start").count();
            if op == "reg_start" && plain == self.refuse {
                return Err(tornect_core::unattended::guard::ReAuthError::Denied);
            }
            Ok(())
        }
    }

    /// An installed copy on a Windows administrator account, UAC at its
    /// defaults: the administrator level exists there.
    fn windows_admin() -> tornect_core::levels::AccountFacts {
        tornect_core::levels::AccountFacts::Windows(tornect_core::levels::WindowsFacts {
            installed: true,
            enable_lua: Some(1),
            filter_administrator_token: Some(0),
            consent_prompt_behavior_user: Some(3),
            consent_prompt_behavior_admin: Some(5),
            prompt_on_secure_desktop: Some(1),
            administrator: true,
            ..Default::default()
        })
    }

    /// The command line's offline route over a store of its own, on `facts`,
    /// asking `reauth`; unattended access on.
    fn admin_route(
        tmp: &tempfile::TempDir,
        facts: tornect_core::levels::AccountFacts,
        reauth: Arc<dyn tornect_core::unattended::guard::ReAuth>,
    ) -> (Paths, Route) {
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
        let guard = MutationGuard::new(
            store,
            reauth,
            Arc::new(NoSessionActivity),
            Arc::new(tornect_core::levels::FixedFacts::new(
                facts,
                tornect_core::levels::HelperPresence::Absent,
            )),
        )
        .with_paired_devices(Arc::new(AllowAllPaired))
        .with_server_setup_source(Arc::new(
            tornect_signal::unattended::OpaqueServerSetupSource,
        ));
        let ctx = HostContext {
            guard: Arc::new(guard),
            host_onion_pk: HOST_PK,
            readiness: SharedReadiness::default(),
            autostart: Arc::new(FakeAutostart::default()),
            user_inputs: vec!["tornect".to_owned()],
            kill: None,
            log,
            facts: Arc::new(tornect_core::levels::FixedFacts::new(
                facts,
                tornect_core::levels::HelperPresence::Absent,
            )),
            show: None,
        };
        assert!(go(&ctx, IpcOp::On).ok);
        (paths, Route::Offline(Box::new(ctx)))
    }

    fn guard_of(route: &Route) -> &MutationGuard {
        let Route::Offline(ctx) = route else {
            panic!("an offline route")
        };
        &ctx.guard
    }

    fn device(seed: u8) -> DeviceId {
        DeviceId::from_bytes(
            *ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
                .verifying_key()
                .as_bytes(),
        )
    }

    /// A plain Control grant with a chosen password, as `grant` makes one.
    fn plain_grant(route: &Route, device: &DeviceId) {
        guard_of(route)
            .create_grant(
                Actor::Cli,
                device,
                Preset::HeadlessBox,
                &GrantOptions::default(),
                &[0u8; 192],
                false,
            )
            .unwrap();
    }

    /// §B.8.7.4: off a terminal, a generated password is refused before
    /// `RegStart`, so nothing is registered: no dialog asked, no grant made,
    /// nothing printed. Shown failing first (without the check, the raise's
    /// dialog was asked and the grant made).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_generated_password_is_refused_off_a_terminal() {
        let tmp = tempfile::tempdir().unwrap();
        let reauth = Arc::new(AllowAllReAuth::default());
        let (paths, route) = admin_route(&tmp, windows_admin(), reauth.clone());
        let asked_before = reauth.calls().len();
        let target = device(41);
        let mut io = Script::new(false, &[]);
        let err = administrator_form(
            &paths,
            &route,
            target,
            Some((Preset::HeadlessBox, false)),
            &mut io,
        )
        .await
        .expect_err("refused off a terminal");
        assert_eq!(err.to_string(), GENERATED_OFF_TERMINAL);
        assert_eq!(reauth.calls().len(), asked_before, "no dialog: no RegStart");
        assert!(guard_of(&route).store().grant(&target).is_none());
        assert!(io.out.is_empty(), "{:?}", io.out);
    }

    /// §B.8.7.4: the default-yes question. Enter, `y` and `yes` are yes; `n`,
    /// any other answer, end of input, a read error and an input that is not a
    /// terminal (all `None`) are no.
    #[test]
    fn the_offer_defaults_to_yes_and_reads_no_from_end_of_input() {
        for yes in ["\n", "", "y\n", "Y", "yes\r\n", " YES "] {
            assert!(default_yes(Some(yes)), "{yes:?}");
        }
        for no in ["n\n", "no", "maybe", "q"] {
            assert!(!default_yes(Some(no)), "{no:?}");
        }
        assert!(
            !default_yes(None),
            "end of input, a read error, not a terminal"
        );
        assert_eq!(OFFER_QUESTION, "Give them new passwords now? [Y/n]");
    }

    /// A22, the command line (§B.8.7.4, D4, D5): `grant --administrator` on a
    /// Windows host prints ⑤a's warning first, creates the admin grant with a
    /// generated password printed once with the line after it, then lists the
    /// other Control grants under ⑤a's heading (no mark label) and asks; yes
    /// gives each a new generated password (each unmarked after it); a view-only
    /// grant is not listed. Then a second rise (`set-password --administrator`
    /// of another grant) prints the warning first too and offers again; no gives
    /// the line that nothing changed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a22_cli_grant_administrator_lists_the_other_control_grants_and_offers_new_passwords() {
        let tmp = tempfile::tempdir().unwrap();
        let reauth = Arc::new(AllowAllReAuth::default());
        let (paths, route) = admin_route(&tmp, windows_admin(), reauth.clone());
        let (a, b, viewer) = (device(42), device(43), device(44));
        plain_grant(&route, &a);
        plain_grant(&route, &b);
        guard_of(&route)
            .create_grant(
                Actor::Cli,
                &viewer,
                Preset::HeadlessBox,
                &GrantOptions {
                    mode: Some(tornect_core::session_log::SessionMode::ViewOnly),
                    ..GrantOptions::default()
                },
                &[0u8; 192],
                false,
            )
            .unwrap();
        let target = device(45);
        let mut io = Script::new(true, &[Some("\n")]);
        administrator_form(
            &paths,
            &route,
            target,
            Some((Preset::HeadlessBox, false)),
            &mut io,
        )
        .await
        .unwrap();
        let store = guard_of(&route).store();
        let made = store.grant(&target).unwrap();
        assert!(made.holds_level() && !made.marked(), "{made:?}");
        assert!(
            io.err[0].starts_with("An unattended administrator session can change anything")
                && io.err[0].contains(&target.fingerprint()),
            "the warning first, naming the device: {:?}",
            io.err
        );
        let heading = &io.err[1];
        assert!(heading.starts_with("These devices have control of this computer: "));
        assert!(heading.contains(&a.fingerprint()) && heading.contains(&b.fingerprint()));
        assert!(
            !heading.contains(&viewer.fingerprint()),
            "view only: not listed"
        );
        assert!(
            !heading.contains("view only until"),
            "no mark label: {heading}"
        );
        assert_eq!(io.asked, vec![OFFER_QUESTION.to_owned()]);
        assert_eq!(
            io.out.len(),
            6,
            "three passwords, each with its line: {:?}",
            io.out
        );
        for pair in io.out.chunks(2) {
            assert!(pair[0].starts_with("New password for \""));
            let words = pair[0].rsplit(": ").next().unwrap();
            // five list words, printed as registered: a hyphenated one as two
            assert!((5..=10).contains(&words.split(' ').count()), "{words}");
            assert_eq!(
                tornect_core::unattended::password::normalize(words).as_str(),
                words
            );
            assert_eq!(pair[1], WRITE_IT_DOWN);
        }
        for other in [&a, &b] {
            assert!(
                !store.grant(other).unwrap().marked(),
                "a generated password unmarks"
            );
        }
        assert!(store.grant(&viewer).unwrap().marked(), "not changed");

        // While a grant holds the level, a plain Control grant cannot be created
        // with a chosen password (D3): the plain form leaves nothing behind.
        let refused = guard_of(&route).create_grant(
            Actor::Cli,
            &device(46),
            Preset::HeadlessBox,
            &GrantOptions::default(),
            &[0u8; 192],
            false,
        );
        assert!(refused.is_err(), "{refused:?}");

        // A second rise (`set-password --administrator` of another grant) offers
        // again; no leaves the others' passwords as they are.
        let mut io = Script::new(true, &[Some("n\n")]);
        administrator_form(&paths, &route, a, None, &mut io)
            .await
            .unwrap();
        assert!(store.grant(&a).unwrap().holds_level());
        assert!(
            io.err[0].starts_with("An unattended administrator session can change anything")
                && io.err[0].contains(&a.fingerprint()),
            "the warning first for set-password --administrator too: {:?}",
            io.err
        );
        assert!(
            io.err[1].contains(&b.fingerprint()) && io.err[1].contains(&target.fingerprint()),
            "{:?}",
            io.err
        );
        assert_eq!(io.err.last().unwrap(), "Their passwords were not changed.");
        assert_eq!(
            io.out.len(),
            2,
            "only the raised grant's password: {:?}",
            io.out
        );
    }

    /// Whether `password` logs in to `device`'s grant, the PAKE run as a host and a
    /// client run it (§B.8.4.4) against the record the grant holds now.
    fn logs_in(paths: &Paths, route: &Route, device: &DeviceId, password: &str) -> bool {
        use tornect_core::unattended::grant::AuthRecord;
        use tornect_signal::auth;
        let store = guard_of(route).store();
        let setup = auth::parse_server_setup(&store.server_setup().unwrap()).unwrap();
        let AuthRecord::Opaque { record } = store.grant(device).unwrap().auth else {
            return false;
        };
        let record = auth::parse_record(&record).unwrap();
        let host_pk = host_onion_pk(paths).unwrap();
        let ids = || auth::identifiers(device.public_key_bytes(), &host_pk);
        let ctx = auth::context(&[0x11; 32], auth::SUITE_OPAQUE, 0);
        let (login, ke1) = auth::ClientLogin::start(password).unwrap();
        let (host, ke2) = auth::HostLogin::start(
            &setup,
            &record,
            &ke1,
            device.public_key_bytes(),
            &ctx,
            ids(),
        )
        .unwrap();
        match login.finish(password, &ke2, &ctx, ids()) {
            Ok(out) => host.finish(&out.ke3, &ctx, ids()).is_ok(),
            Err(_) => false,
        }
    }

    /// §B.8.7.2, §B.8.7.4: a generated password is printed as it is registered
    /// (normalized: a list word's hyphen prints as a space), and the printed text logs
    /// in; another password does not.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_generated_password_is_printed_as_registered_and_logs_in() {
        let tmp = tempfile::tempdir().unwrap();
        let reauth = Arc::new(AllowAllReAuth::default());
        let (paths, route) = admin_route(&tmp, windows_admin(), reauth);
        let target = device(47);
        let mut io = Script::new(true, &[]);
        administrator_form(
            &paths,
            &route,
            target,
            Some((Preset::HeadlessBox, false)),
            &mut io,
        )
        .await
        .unwrap();
        assert_eq!(io.out.len(), 2, "{:?}", io.out);
        let printed = io.out[0].rsplit(": ").next().unwrap();
        assert_eq!(
            tornect_core::unattended::password::normalize(printed).as_str(),
            printed
        );
        assert!(!printed.contains('-'), "{printed}");
        assert!(logs_in(&paths, &route, &target, printed), "{printed}");
        assert!(!logs_in(
            &paths,
            &route,
            &target,
            "quiet verdant otter lantern zephyr"
        ));
    }

    /// §B.8.7.4 (the operator's ruling of 2026-10-02): `set-password
    /// --administrator` prints ⑤a's warning, naming the device, before it raises
    /// the grant, as `grant --administrator` does before it creates one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn set_password_administrator_prints_the_warning_before_the_raise() {
        let tmp = tempfile::tempdir().unwrap();
        let reauth = Arc::new(AllowAllReAuth::default());
        let (paths, route) = admin_route(&tmp, windows_admin(), reauth);
        let target = device(51);
        plain_grant(&route, &target);
        let mut io = Script::new(true, &[]);
        administrator_form(&paths, &route, target, None, &mut io)
            .await
            .unwrap();
        assert_eq!(
            io.err[0],
            tornect_core::levels::ADMINISTRATOR_WARNING.replace("<device>", &target.fingerprint())
        );
        assert!(
            guard_of(&route)
                .store()
                .grant(&target)
                .unwrap()
                .holds_level()
        );
        assert_eq!(io.out.len(), 2, "the password and its line: {:?}", io.out);
    }

    /// D4 (decision M1-67): the plain `grant` and `set-password` register a chosen
    /// password, never as generated and never raising. Each asks the plain dialog;
    /// a plain password change leaves the password marked, of a grant at reach 0
    /// and of one at the level alike; a new Control grant that would reach the
    /// level is refused `G_NEEDS_PASSWORD`, nothing written.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_plain_forms_send_a_chosen_password_and_no_raise() {
        const CHOSEN: &str = "quiet verdant otter lantern zephyr";
        let chosen = || zeroize::Zeroizing::new(CHOSEN.to_owned());
        let tmp = tempfile::tempdir().unwrap();
        let reauth = Arc::new(AllowAllReAuth::default());
        let (paths, route) = admin_route(&tmp, windows_admin(), reauth.clone());
        let store = guard_of(&route).store();
        let (plain, admin, newcomer) = (device(48), device(49), device(50));
        // a grant at reach 0: the plain dialog, the chosen password, still marked
        plain_grant(&route, &plain);
        let asked = reauth.calls().len();
        register_with(&paths, &route, plain, None, false, chosen())
            .await
            .unwrap();
        assert_eq!(reauth.calls()[asked..], ["reg_start".to_owned()]);
        assert!(store.grant(&plain).unwrap().marked());
        assert!(logs_in(&paths, &route, &plain, CHOSEN));
        // a grant at the level (generated, so unmarked): a plain change marks it
        let mut io = Script::new(true, &[Some("n\n")]);
        administrator_form(
            &paths,
            &route,
            admin,
            Some((Preset::HeadlessBox, false)),
            &mut io,
        )
        .await
        .unwrap();
        assert!(!store.grant(&admin).unwrap().marked());
        let asked = reauth.calls().len();
        register_with(&paths, &route, admin, None, false, chosen())
            .await
            .unwrap();
        assert_eq!(reauth.calls()[asked..], ["reg_start".to_owned()]);
        let after = store.grant(&admin).unwrap();
        assert!(after.holds_level() && after.marked(), "{after:?}");
        // a new Control grant, where control now reaches the level: refused
        let asked = reauth.calls().len();
        let err = register_with(
            &paths,
            &route,
            newcomer,
            Some(Preset::HeadlessBox),
            false,
            chosen(),
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string()
                .contains(&format!("(0x{:04x})", codes::G_NEEDS_PASSWORD)),
            "{err:#}"
        );
        assert_eq!(reauth.calls()[asked..], ["reg_start".to_owned()]);
        assert!(store.grant(&newcomer).is_none(), "nothing written");
    }

    /// §B.8.7.1 ⑤a: a *Change password* whose prompt is cancelled keeps that
    /// device's old password; the list is shown again with the devices that
    /// still have it, and asked again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_cancelled_prompt_shows_the_list_again() {
        let tmp = tempfile::tempdir().unwrap();
        let reauth = Arc::new(CancelOne {
            calls: std::sync::Mutex::new(Vec::new()),
            refuse: 2,
        });
        let (paths, route) = admin_route(&tmp, windows_admin(), reauth);
        let (a, b) = (device(47), device(48));
        plain_grant(&route, &a);
        plain_grant(&route, &b);
        let mut io = Script::new(true, &[Some("\n"), Some("y\n")]);
        administrator_form(
            &paths,
            &route,
            device(49),
            Some((Preset::HeadlessBox, false)),
            &mut io,
        )
        .await
        .unwrap();
        let store = guard_of(&route).store();
        assert_eq!(io.asked.len(), 2, "asked again: {:?}", io.err);
        let again = io
            .err
            .iter()
            .find(|l| l.starts_with("These devices still have their old password: "))
            .expect("the list again");
        assert!(
            again.contains(&a.fingerprint()) != again.contains(&b.fingerprint()),
            "only the device whose prompt was cancelled: {again}"
        );
        assert!(io.err.iter().any(|l| l.contains("keeps its old password")));
        assert!(!store.grant(&a).unwrap().marked() && !store.grant(&b).unwrap().marked());
        assert_eq!(io.out.len(), 6, "{:?}", io.out);
    }

    /// §B.8.7.4 on Linux: the administrator forms are refused with the plan's
    /// sentence, before any dialog, and nothing is printed or registered.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a22_cli_on_linux_the_administrator_forms_are_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let reauth = Arc::new(AllowAllReAuth::default());
        let (paths, route) = admin_route(
            &tmp,
            tornect_core::levels::AccountFacts::Linux,
            reauth.clone(),
        );
        let asked_before = reauth.calls().len();
        let target = device(50);
        let mut io = Script::new(true, &[]);
        let err = administrator_form(
            &paths,
            &route,
            target,
            Some((Preset::HeadlessBox, false)),
            &mut io,
        )
        .await
        .expect_err("refused on Linux");
        assert!(
            err.to_string()
                .starts_with("Administrator access does not exist on Linux: Tornect runs as you."),
            "{err}"
        );
        assert_eq!(reauth.calls().len(), asked_before, "no dialog");
        assert!(io.out.is_empty());
        assert!(guard_of(&route).store().grant(&target).is_none());
    }

    // ------------------------------------------------ set-level <device> none

    /// Every device end the guard asks for, in order.
    #[derive(Default)]
    struct RecordingEnd {
        ended: std::sync::Mutex<Vec<(DeviceId, EndScope)>>,
    }

    impl RecordingEnd {
        fn take(&self) -> Vec<(DeviceId, EndScope)> {
            std::mem::take(&mut *self.ended.lock().unwrap())
        }
    }

    impl DeviceSessionEnd for RecordingEnd {
        fn end_device(&self, device: &DeviceId, scope: EndScope) {
            self.ended.lock().unwrap().push((*device, scope));
        }
    }

    /// A host context where grants can hold the administrator level: an
    /// installed copy on a Windows administrator account's facts (the helper
    /// task's presence as `facts` says), re-authentication allowed and
    /// recorded, sessions as `activity` says, device ends recorded;
    /// unattended access on.
    struct LevelEnv {
        tmp: tempfile::TempDir,
        ctx: HostContext,
        facts: Arc<tornect_core::levels::FixedFacts>,
        activity: Arc<ScriptedActivity>,
        ended: Arc<RecordingEnd>,
        reauth: Arc<AllowAllReAuth>,
    }

    fn level_env() -> LevelEnv {
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
        let facts = Arc::new(tornect_core::levels::FixedFacts::new(
            windows_admin(),
            tornect_core::levels::HelperPresence::Absent,
        ));
        let activity = Arc::new(ScriptedActivity::default());
        let ended = Arc::new(RecordingEnd::default());
        let reauth = Arc::new(AllowAllReAuth::default());
        let guard = MutationGuard::new(
            store,
            Arc::clone(&reauth) as Arc<dyn tornect_core::unattended::guard::ReAuth>,
            Arc::clone(&activity) as Arc<dyn RemoteSessionActivity>,
            Arc::clone(&facts) as Arc<dyn FactsSource>,
        )
        .with_paired_devices(Arc::new(AllowAllPaired))
        .with_server_setup_source(Arc::new(
            tornect_signal::unattended::OpaqueServerSetupSource,
        ))
        .with_device_end(Arc::clone(&ended) as Arc<dyn DeviceSessionEnd>);
        let ctx = HostContext {
            guard: Arc::new(guard),
            host_onion_pk: HOST_PK,
            readiness: SharedReadiness::default(),
            autostart: Arc::new(FakeAutostart::default()),
            user_inputs: vec!["tornect".to_owned()],
            kill: None,
            log,
            facts: Arc::clone(&facts) as Arc<dyn FactsSource>,
            show: None,
        };
        assert!(go(&ctx, IpcOp::On).ok);
        LevelEnv {
            tmp,
            ctx,
            facts,
            activity,
            ended,
            reauth,
        }
    }

    impl LevelEnv {
        /// A grant at the administrator level (a generated password), with
        /// `options` besides.
        fn admin_grant(&self, device: &DeviceId, options: GrantOptions) {
            self.ctx
                .guard
                .create_grant(
                    Actor::Cli,
                    device,
                    Preset::HeadlessBox,
                    &GrantOptions {
                        elevation: Some(tornect_core::levels::Elevation::Admin),
                        ..options
                    },
                    &[0u8; 192],
                    true,
                )
                .unwrap();
        }

        /// A Control grant at none, before any grant holds the level.
        fn plain_grant(&self, device: &DeviceId) {
            self.ctx
                .guard
                .create_grant(
                    Actor::Cli,
                    device,
                    Preset::HeadlessBox,
                    &GrantOptions::default(),
                    &[0u8; 192],
                    false,
                )
                .unwrap();
        }

        /// The same store behind a guard that refuses every re-authentication.
        fn refusing(&self) -> HostContext {
            let guard = MutationGuard::new(
                self.ctx.guard.store().clone(),
                Arc::new(DenyAllReAuth),
                Arc::clone(&self.activity) as Arc<dyn RemoteSessionActivity>,
                Arc::clone(&self.facts) as Arc<dyn FactsSource>,
            )
            .with_device_end(Arc::clone(&self.ended) as Arc<dyn DeviceSessionEnd>);
            HostContext {
                guard: Arc::new(guard),
                host_onion_pk: HOST_PK,
                readiness: SharedReadiness::default(),
                autostart: Arc::new(autostart::NoAutostart("test".to_owned())),
                user_inputs: Vec::new(),
                kill: None,
                log: self.ctx.log.clone(),
                facts: Arc::clone(&self.facts) as Arc<dyn FactsSource>,
                show: None,
            }
        }

        fn grant(&self, device: &DeviceId) -> tornect_core::unattended::grant::UnattendedGrant {
            self.ctx.guard.store().grant(device).unwrap()
        }
    }

    fn keeps(resp: &IpcResponse) -> u8 {
        decode_payload::<SetLevelNonePayload>(resp.payload.as_deref().expect("a payload"))
            .unwrap()
            .keeps
    }

    /// Decision M1-68, §B.8.6.2's deny-direction row: `set-level none` takes
    /// the level away with no re-authentication, also while a remote session
    /// is live. Shown failing first: this build refused it (`G_UNSUPPORTED`).
    #[test]
    fn set_level_none_needs_no_reauth_and_lowers() {
        let env = level_env();
        let target = device(61);
        env.admin_grant(&target, GrantOptions::default());
        assert!(env.grant(&target).holds_level());
        env.activity.set_live(true);
        let refusing = env.refusing();
        let resp = go(&refusing, IpcOp::SetLevelNone { device: target });
        assert!(resp.ok, "{resp:?}");
        assert_eq!(resp.detail, None, "lowered, so no unchanged note");
        assert!(!env.grant(&target).holds_level());
        assert_eq!(keeps(&resp), SetLevelNonePayload::NOTHING);
    }

    /// FC-4: the guard is sent the level and nothing else, built from nothing
    /// read: every other field of the grant stays as it was.
    #[test]
    fn set_level_none_sends_only_the_elevation() {
        assert_eq!(
            level_none_options(),
            GrantOptions {
                elevation: Some(tornect_core::levels::Elevation::None),
                ..GrantOptions::default()
            }
        );
        let env = level_env();
        let target = device(62);
        env.admin_grant(
            &target,
            GrantOptions {
                label: Some("Desk".to_owned()),
                block_window_s: Some(17),
                max_session_secs: Some(1234),
                require_tor_only: Some(true),
                ..GrantOptions::default()
            },
        );
        let before = env.grant(&target);
        assert!(go(&env.ctx, IpcOp::SetLevelNone { device: target }).ok);
        let after = env.grant(&target);
        let mut expected = before.clone();
        expected.elevation = tornect_core::levels::Elevation::None;
        assert!(after == expected, "only the level changed:\n{after:?}");
    }

    /// FC-4: a change made after the command line read the grant is kept (the
    /// level goes alone, so nothing stale rides with it), and nothing asks for
    /// a dialog: a refusing re-authentication never runs.
    #[test]
    fn set_level_none_never_reaches_reauth() {
        let env = level_env();
        let target = device(63);
        env.admin_grant(&target, GrantOptions::default());
        let dialogs = env.reauth.calls().len();
        // the narrowing made meanwhile: control → view only (deny-direction)
        env.ctx
            .guard
            .set_options(
                Actor::Ui,
                &target,
                &GrantOptions {
                    mode: Some(tornect_core::session_log::SessionMode::ViewOnly),
                    ..GrantOptions::default()
                },
            )
            .unwrap();
        let resp = go(&env.refusing(), IpcOp::SetLevelNone { device: target });
        assert!(resp.ok, "{resp:?}");
        let after = env.grant(&target);
        assert_eq!(after.mode, tornect_core::session_log::SessionMode::ViewOnly);
        assert!(!after.holds_level());
        assert_eq!(env.reauth.calls().len(), dialogs, "no dialog asked");
    }

    /// The op carries no level: whatever the grant holds, it ends at none.
    #[test]
    fn set_level_none_never_raises() {
        let env = level_env();
        let (plain, admin) = (device(64), device(65));
        env.plain_grant(&plain);
        env.admin_grant(&admin, GrantOptions::default());
        for target in [plain, admin, plain] {
            assert!(go(&env.ctx, IpcOp::SetLevelNone { device: target }).ok);
            assert!(!env.grant(&target).holds_level());
        }
        assert!(!env.grant(&plain).holds_level() && !env.grant(&admin).holds_level());
    }

    /// D6: a lowering ends that device's sessions at the administrator level
    /// only (a session below the level goes on), and no other device's.
    #[test]
    fn set_level_none_ends_only_the_admin_session() {
        let env = level_env();
        let (target, other) = (device(66), device(67));
        env.admin_grant(&target, GrantOptions::default());
        env.admin_grant(&other, GrantOptions::default());
        env.ended.take();
        assert!(go(&env.ctx, IpcOp::SetLevelNone { device: target }).ok);
        assert_eq!(env.ended.take(), vec![(target, EndScope::AtTheLevel)]);
        assert!(env.grant(&other).holds_level(), "another device untouched");
        // nothing left to lower: nothing ends
        assert!(go(&env.ctx, IpcOp::SetLevelNone { device: target }).ok);
        assert!(env.ended.take().is_empty());
    }

    /// A grant without the level is left as it is: the answer is ok and says
    /// so, every field stays, and no session ends.
    #[test]
    fn set_level_none_on_a_grant_at_none_changes_nothing() {
        let env = level_env();
        let target = device(68);
        env.plain_grant(&target);
        let before = env.grant(&target);
        env.ended.take();
        let resp = go(&env.ctx, IpcOp::SetLevelNone { device: target });
        assert!(resp.ok, "{resp:?}");
        assert_eq!(resp.detail.as_deref(), Some(LEVEL_ALREADY_NONE));
        assert_eq!(keeps(&resp), SetLevelNonePayload::NOTHING);
        assert!(env.grant(&target) == before, "unchanged");
        assert!(env.ended.take().is_empty());
        // a device with no grant is refused by the guard, nothing changed
        let resp = go(&env.ctx, IpcOp::SetLevelNone { device: device(69) });
        assert!(!resp.ok);
        assert_eq!(resp.code, codes::G_PRECONDITION, "{resp:?}");
    }

    /// M1-46 (kept): a host that started without its store answers `tornect
    /// panic` only; `set-level none` is refused with that reason and ends
    /// nothing.
    #[test]
    fn a_storeless_host_refuses_set_level_none() {
        let kill = KillSwitch::new();
        let resp = dispatch_without_store(
            &kill,
            "the store is locked",
            IpcRequest {
                id: 4,
                op: IpcOp::SetLevelNone { device: device(70) },
            },
        );
        assert!(!resp.ok);
        assert_eq!(resp.code, codes::G_PRECONDITION);
        assert!(
            resp.detail
                .as_deref()
                .is_some_and(|d| d.contains("answers only `tornect panic`")),
            "{resp:?}"
        );
        assert_eq!(kill.fired(), None);
    }

    /// Only `none` is a level `set-level` takes (decision M1-68): the command
    /// cannot raise.
    #[test]
    fn set_level_parses_only_none() {
        #[derive(clap::Parser, Debug)]
        struct Cli {
            #[command(subcommand)]
            cmd: UnattendedCmd,
        }
        let parse = |args: &[&str]| {
            <Cli as clap::Parser>::try_parse_from(["unattended"].iter().chain(args))
        };
        let parsed = parse(&["set-level", "Laptop", "none"]).unwrap();
        assert!(
            matches!(
                parsed.cmd,
                UnattendedCmd::SetLevel { ref device, level: LevelArg::None } if device == "Laptop"
            ),
            "{parsed:?}"
        );
        for level in ["administrator", "admin", "None", "NONE", "view", ""] {
            assert!(
                parse(&["set-level", "Laptop", level]).is_err(),
                "{level:?} parsed"
            );
        }
        assert!(
            parse(&["set-level", "Laptop"]).is_err(),
            "the level is required"
        );
    }

    /// The command line prints the turn-off sentence (§B.8.7.1 ⑤a) after a
    /// lowering, and the unchanged line for a grant without the level.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn set_level_prints_the_turn_off_sentence() {
        let env = level_env();
        let (target, plain) = (device(71), device(72));
        env.plain_grant(&plain);
        env.admin_grant(&target, GrantOptions::default());
        let paths = Paths::from_home(env.tmp.path());
        let route = Route::Offline(Box::new(env.refusing()));
        let mut io = Script::new(true, &[]);
        set_level_none_cli(&paths, &route, target, &mut io)
            .await
            .unwrap();
        let label = target.fingerprint();
        assert_eq!(io.out, vec![LEVEL_OFF.replace("<device>", &label)]);
        assert_eq!(
            io.out[0],
            format!(
                "Administrator access is off for {label}. A session of {label} running as \
                 administrator ends now."
            )
        );
        assert!(io.err.is_empty() && io.asked.is_empty());
        assert!(!env.grant(&target).holds_level());
        let mut io = Script::new(true, &[]);
        set_level_none_cli(&paths, &route, plain, &mut io)
            .await
            .unwrap();
        assert_eq!(
            io.out,
            vec![format!(
                "{} has no administrator access; nothing changed.",
                plain.fingerprint()
            )]
        );
    }

    /// The turn-off sentence's condition (§B.8.7.1 ⑤a): while another grant
    /// holds the level, then while the helper task stays registered.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn set_level_prints_the_turn_off_sentence_with_its_condition() {
        let env = level_env();
        let (first, second) = (device(73), device(74));
        env.admin_grant(&first, GrantOptions::default());
        env.admin_grant(&second, GrantOptions::default());
        let paths = Paths::from_home(env.tmp.path());
        let facts = Arc::clone(&env.facts);
        let route = Route::Offline(Box::new(env.refusing()));
        let mut io = Script::new(true, &[]);
        set_level_none_cli(&paths, &route, first, &mut io)
            .await
            .unwrap();
        let label = first.fingerprint();
        assert_eq!(
            io.out,
            vec![
                LEVEL_OFF.replace("<device>", &label),
                format!(
                    "{label} keeps control of this computer. While another device has \
                     administrator access, control can still reach programs that run as \
                     administrator. To stop that now, set {label} to View only."
                ),
            ]
        );
        // the last admin grant, with the helper task still registered
        facts.set_helper_task(tornect_core::levels::HelperPresence::Registered);
        let mut io = Script::new(true, &[]);
        set_level_none_cli(&paths, &route, second, &mut io)
            .await
            .unwrap();
        let label = second.fingerprint();
        assert_eq!(
            io.out,
            vec![
                LEVEL_OFF.replace("<device>", &label),
                format!(
                    "{label} keeps control of this computer. While the administrator helper is \
                     still registered: Tornect removes it the next time you sign in here, control \
                     can still reach programs that run as administrator. To stop that now, set \
                     {label} to View only."
                ),
            ]
        );
        // nothing left: a presence that cannot be read still counts
        facts.set_helper_task(tornect_core::levels::HelperPresence::Unreadable);
        let resp = go(
            match &route {
                Route::Offline(ctx) => ctx,
                Route::Host => unreachable!(),
            },
            IpcOp::SetLevelNone { device: second },
        );
        assert_eq!(keeps(&resp), SetLevelNonePayload::HELPER_TASK);
        facts.set_helper_task(tornect_core::levels::HelperPresence::Absent);
        let resp = go(
            match &route {
                Route::Offline(ctx) => ctx,
                Route::Host => unreachable!(),
            },
            IpcOp::SetLevelNone { device: second },
        );
        assert_eq!(keeps(&resp), SetLevelNonePayload::NOTHING);
    }
}
