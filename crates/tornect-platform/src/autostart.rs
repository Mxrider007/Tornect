//! Start at login (`docs/PLAN.md` §B.8.7.5): a **user-level** registration that
//! starts this executable after the user logs in: on Windows the window,
//! minimised (`tornect --background`, §B.1.1), on Linux the `host` command.
//!
//! | OS | Mechanism | Registered as |
//! |---|---|---|
//! | Linux | systemd user unit, `WantedBy=graphical-session.target` | `~/.config/systemd/user/tornect-host.service` |
//! | Windows | Task Scheduler, a logon trigger for this user only | task `\Tornect` |
//!
//! Every variant starts **after** a login: Tornect never configures auto-login,
//! so a machine that reboots to a login screen stays offline until someone logs
//! in (§B.8.7.5, B.8.7.1 ⑥). The elevated Windows task is strictly opt-in: it
//! makes every remote Control session an administrator session (T9, §B.8.8).
//!
//! Changing the registration is access-increasing (§B.8.6.2): the host's
//! dispatch calls [`Autostart::install`] / [`Autostart::uninstall`] only after
//! the mutation guard's re-authentication. This module performs the effect and
//! nothing else; [`Autostart::status`] and [`readiness_probe`] are read-only.
//!
//! **Paths.** Every executable is named by an absolute path — `systemctl` from
//! `/usr/bin` or `/bin`, `schtasks.exe` from the Windows system directory — and
//! never looked up on `PATH`. Every path written into a registration is quoted
//! for the reader that parses it (systemd's command-line rules, the Task
//! Scheduler's command field); a path that cannot be quoted is refused, never
//! written half-escaped.

use std::ffi::OsString;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::Arc;

use tornect_core::unattended::readiness::Probe;

/// The Windows Task Scheduler task, in the root folder (`\Tornect`).
pub const TASK_NAME: &str = "Tornect";

/// The systemd user unit (§B.8.7.5 names it).
pub const UNIT_NAME: &str = "tornect-host.service";

/// What a registration runs: the systemd user unit `<exe> [--home <dir>] host`
/// ([`LaunchSpec::args`]), the at-logon task the app in the background
/// ([`LaunchSpec::app_args`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchSpec {
    /// Absolute path of the `tornect` executable.
    pub exe: PathBuf,
    /// `--home <dir>` when the registering command used a custom home
    /// (`--home` / `TORNECT_HOME`); `None` for the platform's default
    /// directories, which the started host then finds by itself.
    pub home: Option<PathBuf>,
}

impl LaunchSpec {
    /// The arguments after the executable.
    #[must_use]
    pub fn args(&self) -> Vec<OsString> {
        let mut args = Vec::new();
        if let Some(home) = &self.home {
            args.push(OsString::from("--home"));
            args.push(home.clone().into_os_string());
        }
        args.push(OsString::from("host"));
        args
    }

    /// The arguments after the executable for the app started in the
    /// background (§B.1.1, decision M1-58): `[--home <dir>] --background`,
    /// what the at-logon task runs.
    #[must_use]
    pub fn app_args(&self) -> Vec<OsString> {
        let mut args = Vec::new();
        if let Some(home) = &self.home {
            args.push(OsString::from("--home"));
            args.push(home.clone().into_os_string());
        }
        args.push(OsString::from("--background"));
        args
    }
}

/// What is registered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutostartState {
    /// A registration exists.
    Registered(Registration),
    /// Nothing is registered.
    Absent,
    /// This host has no mechanism for it (no systemd user manager, or an OS
    /// without a backend). The reason, for the operator.
    Unavailable(String),
}

/// An existing registration.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Registration {
    /// Whether it starts at the next login. `false`: registered but disabled
    /// (systemd `disabled`/`masked`/`linked`, a disabled task, a task with no
    /// logon trigger); [`Self::note`] says which.
    pub enabled: bool,
    /// The Windows elevated task (`RunLevel` `HighestAvailable`).
    pub elevated: bool,
    /// The registered command line, as the mechanism stores it.
    pub command: Option<String>,
    /// Why a registration is not enabled, in the mechanism's words; for an
    /// [`Self::unreadable`] one, what is known about it.
    pub note: Option<String>,
    /// Known to exist but not readable by this account (a Windows task
    /// registered from an administrator prompt): whether it is enabled or
    /// elevated is unknown, so it is treated as possibly elevated.
    pub unreadable: bool,
}

/// Why a registration change did not happen.
#[derive(Debug, thiserror::Error)]
pub enum AutostartError {
    /// No mechanism on this host, or not for this request.
    #[error("start at login is unavailable here: {0}")]
    Unavailable(String),
    /// A path that cannot be written into the registration safely.
    #[error("cannot register this command: {0}")]
    Unquotable(String),
    /// The user dismissed the administrator (UAC) prompt.
    #[error("the administrator prompt was cancelled; nothing was changed")]
    Cancelled,
    /// The OS tool failed.
    #[error("{0}")]
    Failed(String),
}

/// The OS registration of §B.8.7.5.
pub trait Autostart: Send + Sync {
    /// Checks that [`Self::install`] could succeed — the mechanism exists, every
    /// path quotes, the elevated task's rules hold — without changing anything.
    /// The dispatch runs it **before** the re-authentication dialog, so nobody
    /// types a password for a change that can never be made.
    fn preflight(&self, elevated: bool) -> Result<(), AutostartError>;

    /// Registers (or re-registers) the host to start at login.
    fn install(&self, elevated: bool) -> Result<AutostartState, AutostartError>;

    /// Removes the registration. Removing an absent one succeeds.
    fn uninstall(&self) -> Result<AutostartState, AutostartError>;

    /// What is registered now. Read-only.
    fn status(&self) -> Result<AutostartState, AutostartError>;

    /// The mechanism, for messages ("systemd user unit tornect-host.service").
    fn describe(&self) -> String;

    /// How to remove the registration by hand, for a message ("remove it
    /// …"): what the user can do when Tornect refuses to.
    fn manual_removal(&self) -> String;
}

/// The readiness row of §B.8.7.1 ⑥ for a [`Autostart::status`] answer.
///
/// `Ok` only for an enabled, non-elevated registration. Everything else raises
/// the badge (`Warn`) — autostart is never a gating row (§B.8.14): an elevated
/// task because of what it means for remote sessions, a missing or disabled
/// one because the host will not be there after a reboot.
#[must_use]
pub fn readiness_probe(status: &Result<AutostartState, AutostartError>) -> Probe {
    match status {
        // Slice-F F1-1: whether it is elevated is unknown, so it is warned as
        // if it were.
        Ok(AutostartState::Registered(r)) if r.unreadable => Probe::Warn(format!(
            "{}: it may start the host ELEVATED at login, and then every remote Control \
             session is an administrator session",
            r.note.as_deref().unwrap_or(UNREADABLE_TASK)
        )),
        Ok(AutostartState::Registered(r)) if r.enabled && r.elevated => Probe::Warn(
            "the host starts ELEVATED at login: every remote Control session is an \
             administrator session; this task is from an earlier version, and `tornect service \
             install` or `uninstall` removes it"
                .to_owned(),
        ),
        Ok(AutostartState::Registered(r)) if r.enabled => Probe::Ok,
        Ok(AutostartState::Registered(r)) => Probe::Warn(format!(
            "registered but it will not start at login ({})",
            r.note.as_deref().unwrap_or("disabled")
        )),
        Ok(AutostartState::Absent) => Probe::Warn(
            "not registered: the host does not start at login (`tornect service install`)"
                .to_owned(),
        ),
        Ok(AutostartState::Unavailable(why)) => {
            Probe::Warn(format!("start at login is unavailable here: {why}"))
        }
        Err(e) => Probe::Warn(format!(
            "could not read the start-at-login registration: {e}"
        )),
    }
}

/// The backend for this OS, running `spec`.
#[must_use]
pub fn for_this_os(spec: LaunchSpec) -> Arc<dyn Autostart> {
    #[cfg(target_os = "linux")]
    {
        match SystemdUserUnit::new(spec) {
            Ok(unit) => Arc::new(unit),
            Err(e) => Arc::new(NoAutostart(e.to_string())),
        }
    }
    #[cfg(windows)]
    {
        match TaskScheduler::new(spec) {
            Ok(task) => Arc::new(task),
            Err(e) => Arc::new(NoAutostart(e.to_string())),
        }
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = spec;
        Arc::new(NoAutostart(
            "this OS has no start-at-login backend yet (docs/PLAN.md §B.8.14 M6)".to_owned(),
        ))
    }
}

/// A host with no mechanism: every change is refused, the status says why.
#[derive(Debug, Clone)]
pub struct NoAutostart(pub String);

impl Autostart for NoAutostart {
    fn preflight(&self, _elevated: bool) -> Result<(), AutostartError> {
        Err(AutostartError::Unavailable(self.0.clone()))
    }

    fn install(&self, _elevated: bool) -> Result<AutostartState, AutostartError> {
        Err(AutostartError::Unavailable(self.0.clone()))
    }

    fn uninstall(&self) -> Result<AutostartState, AutostartError> {
        Err(AutostartError::Unavailable(self.0.clone()))
    }

    fn status(&self) -> Result<AutostartState, AutostartError> {
        Ok(AutostartState::Unavailable(self.0.clone()))
    }

    fn describe(&self) -> String {
        "no start-at-login mechanism".to_owned()
    }

    fn manual_removal(&self) -> String {
        "there is no start-at-login registration to remove here".to_owned()
    }
}

/// The first line of a tool's output that says something, for error messages.
fn first_line(out: &Output) -> String {
    let text = if out.stderr.iter().any(|b| !b.is_ascii_whitespace()) {
        decode_console_output(&out.stderr)
    } else {
        decode_console_output(&out.stdout)
    };
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("no output")
        .chars()
        .take(300)
        .collect()
}

/// Console output as text: UTF-16LE when it carries a BOM or looks like it
/// (`schtasks /Query /XML` writes UTF-16 to a pipe on some systems), else
/// UTF-8 with replacement characters.
#[must_use]
pub fn decode_console_output(bytes: &[u8]) -> String {
    let utf16 = bytes.starts_with(&[0xFF, 0xFE])
        || (bytes.len() >= 4 && bytes.len().is_multiple_of(2) && bytes[1] == 0 && bytes[3] == 0);
    if utf16 {
        let body = bytes.strip_prefix(&[0xFF, 0xFE]).unwrap_or(bytes);
        let units: Vec<u16> = body
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    }
}

// ---------------------------------------------------------------------------
// Where the executable may live (slice-F F2-2, default 1, F1-4, F2-6)
// ---------------------------------------------------------------------------

/// What the location check needs to know of one path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathFacts {
    /// Owner.
    pub uid: u32,
    /// Group.
    pub gid: u32,
    /// Permission bits (`st_mode`).
    pub mode: u32,
    /// A symbolic link rather than what it points to.
    pub symlink: bool,
}

/// Whether the start-at-login unit may run `exe` on a Unix: nobody but this
/// user (`uid`, primary group `gid`) or root can replace it, and systemd
/// takes its path as written (slice-F F2-2, the Linux side of default 1, and
/// F2-6's characters).
///
/// The executable and every directory above it must be owned by root or this
/// user, writable by no other account (a sticky `/tmp`, `/var/tmp` or
/// `/dev/shm` is refused too: another account can re-create a removed entry
/// there), and group-writable only for this user's primary group (a
/// user-private group under umask 002). No component may be a symbolic link:
/// the registered path is the real one (`current_exe` resolves them). `$`,
/// quotes and backslashes are refused in the program path, which systemd does
/// not take as written there.
pub fn unix_exe_location_ok(
    exe: &Path,
    uid: u32,
    gid: u32,
    stat: &dyn Fn(&Path) -> std::io::Result<PathFacts>,
) -> Result<(), AutostartError> {
    let refuse = |why: String| {
        Err(AutostartError::Unavailable(format!(
            "{why}, so another account could change what runs at every login; keep `tornect` in \
             a folder only you (or root) can change, such as ~/.local/bin, and run `tornect \
             service install` from there"
        )))
    };
    if let Some(c) = exe
        .to_string_lossy()
        .chars()
        .find(|c| matches!(c, '$' | '"' | '\'' | '\\'))
    {
        return Err(AutostartError::Unavailable(format!(
            "{} contains {c:?}, which a systemd unit does not take as written in the program's \
             path; move `tornect` to a folder whose path has no `$`, quotes or backslashes",
            exe.display()
        )));
    }
    if !exe.is_absolute() {
        return Err(AutostartError::Unquotable(format!(
            "{} is not an absolute path",
            exe.display()
        )));
    }
    for path in exe.ancestors() {
        let f = match stat(path) {
            Ok(f) => f,
            Err(e) => {
                return refuse(format!(
                    "could not check who can change {}: {e}",
                    path.display()
                ));
            }
        };
        if f.symlink {
            return refuse(format!(
                "{} is a symbolic link, whose target is not what was checked",
                path.display()
            ));
        }
        if f.uid != 0 && f.uid != uid {
            return refuse(format!(
                "{} belongs to another account (uid {})",
                path.display(),
                f.uid
            ));
        }
        if f.mode & 0o002 != 0 {
            return refuse(format!(
                "{} can be changed by every account on this computer",
                path.display()
            ));
        }
        if f.mode & 0o020 != 0 && f.gid != gid {
            return refuse(format!(
                "{} can be changed by the members of group {}",
                path.display(),
                f.gid
            ));
        }
    }
    Ok(())
}

/// The real user and group ids in `/proc/self/status`.
#[must_use]
pub fn parse_status_ids(status: &str) -> Option<(u32, u32)> {
    let field = |name: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(name))
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|v| v.parse().ok())
    };
    Some((field("Uid:")?, field("Gid:")?))
}

/// [`unix_exe_location_ok`] for this process's user, against the real file
/// system.
fn this_users_exe_location_ok(exe: &Path) -> Result<(), AutostartError> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt as _;
        let status = std::fs::read_to_string("/proc/self/status").map_err(|e| {
            AutostartError::Unavailable(format!("could not read who this process runs as: {e}"))
        })?;
        let (uid, gid) = parse_status_ids(&status).ok_or_else(|| {
            AutostartError::Unavailable("/proc/self/status names no user or group".to_owned())
        })?;
        let stat = |p: &Path| {
            std::fs::symlink_metadata(p).map(|m| PathFacts {
                uid: m.uid(),
                gid: m.gid(),
                mode: m.mode(),
                symlink: m.file_type().is_symlink(),
            })
        };
        unix_exe_location_ok(exe, uid, gid, &stat)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = exe;
        Err(AutostartError::Unavailable(
            "a systemd user unit is registered on Linux only".to_owned(),
        ))
    }
}

/// Whether the Windows task may run `exe` (default 1, slice F): the
/// non-elevated task only from under the user's profile or Program Files, the
/// elevated one only from under Program Files. Other accounts cannot change
/// either folder; a folder under `C:\` inherits "Authenticated Users: Modify"
/// (review finding E2-2), so a `tornect.exe` there could be replaced by
/// another account and would run at every login. The folders come from the OS
/// (`SHGetKnownFolderPath`), not from the environment (F1-4); a folder the OS
/// does not name is not guessed.
pub fn windows_exe_location_ok(
    exe: &str,
    elevated: bool,
    profile: Option<&str>,
    program_files: Option<&str>,
) -> Result<(), AutostartError> {
    let program_files: Vec<String> = program_files.map(str::to_owned).into_iter().collect();
    if elevated {
        if location_under(exe, &program_files) {
            return Ok(());
        }
        return Err(AutostartError::Unavailable(format!(
            "the elevated task runs only a tornect.exe under Program Files, which only \
             administrators can change; {exe} is elsewhere, so another account could replace \
             what would run elevated"
        )));
    }
    let mut allowed = program_files;
    allowed.extend(profile.map(str::to_owned));
    if location_under(exe, &allowed) {
        return Ok(());
    }
    Err(AutostartError::Unavailable(format!(
        "the start-at-login task runs only a tornect.exe under your user folder{} or Program \
         Files, which other accounts cannot change; {exe} is elsewhere, so another account could \
         replace what would run at every login; move the Tornect folder there and run \
         `tornect service install` from it",
        profile.map(|p| format!(" ({p})")).unwrap_or_default()
    )))
}

// ---------------------------------------------------------------------------
// Linux: a systemd user unit
// ---------------------------------------------------------------------------

/// Quote one command-line item for a systemd unit (`systemd.service(5)`,
/// "Command lines"): the item goes in double quotes, `\` and `"` are
/// backslash-escaped (C-style escapes are decoded inside quotes), `%` becomes
/// `%%` (specifiers) and `$` becomes `$$` (variable expansion). Control
/// characters and non-UTF-8 text cannot be written into a unit file safely and
/// are refused.
pub fn systemd_quote(item: &std::ffi::OsStr) -> Result<String, AutostartError> {
    let s = item.to_str().ok_or_else(|| {
        AutostartError::Unquotable(format!(
            "{} is not valid UTF-8, which a unit file cannot hold",
            item.to_string_lossy()
        ))
    })?;
    if s.chars().any(char::is_control) {
        return Err(AutostartError::Unquotable(format!(
            "{s:?} contains a control character"
        )));
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '%' => out.push_str("%%"),
            '$' => out.push_str("$$"),
            c => out.push(c),
        }
    }
    out.push('"');
    Ok(out)
}

/// The unit's `ExecStart=` value: every item quoted, the executable absolute.
pub fn systemd_exec_start(spec: &LaunchSpec) -> Result<String, AutostartError> {
    if !spec.exe.is_absolute() {
        return Err(AutostartError::Unquotable(format!(
            "{} is not an absolute path",
            spec.exe.display()
        )));
    }
    if let Some(home) = &spec.home
        && !home.is_absolute()
    {
        return Err(AutostartError::Unquotable(format!(
            "the home {} is not an absolute path",
            home.display()
        )));
    }
    let mut line = systemd_quote(spec.exe.as_os_str())?;
    for arg in spec.args() {
        line.push(' ');
        line.push_str(&systemd_quote(&arg)?);
    }
    Ok(line)
}

/// The unit file `tornect service install` writes.
///
/// - `PartOf=`/`After=`/`WantedBy=graphical-session.target` (§B.8.7.5): the
///   host starts with the graphical session, after the desktop has exported
///   its display and session-bus variables to the user manager (the portal
///   capture needs them), and stops with it.
/// - `KillSignal=SIGINT`: `systemctl --user stop` takes the host's Ctrl-C
///   path, which ends every session with a `BYE`, releases the keys a viewer
///   holds and flushes `sessions.log`, instead of SIGTERM's abrupt default.
/// - `Restart=on-abnormal`: a crash (a signal, a watchdog) restarts the host
///   after 10 s; a clean or failing exit does not, so a host that refuses to
///   start (another one holds this home's lock) does not loop.
pub fn systemd_unit_text(spec: &LaunchSpec) -> Result<String, AutostartError> {
    let exec = systemd_exec_start(spec)?;
    Ok(format!(
        "# Tornect: start the host at login (docs/PLAN.md §B.8.7.5).\n\
         # Written by `tornect service install`; `tornect service uninstall` removes it.\n\
         [Unit]\n\
         Description=Tornect host (started at login)\n\
         PartOf=graphical-session.target\n\
         After=graphical-session.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={exec}\n\
         KillSignal=SIGINT\n\
         Restart=on-abnormal\n\
         RestartSec=10\n\
         \n\
         [Install]\n\
         WantedBy=graphical-session.target\n"
    ))
}

/// One `systemctl --user` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystemctlCall<'a> {
    /// `daemon-reload`: the manager rereads unit files.
    DaemonReload,
    /// `enable <path>`: links the unit into the manager's search path when it
    /// lives outside it, and adds the `WantedBy=` symlink.
    Enable(&'a Path),
    /// `disable <unit>`: removes both.
    Disable(&'a str),
    /// `is-enabled <unit>`.
    IsEnabled(&'a str),
}

/// The argument vector for `call`.
#[must_use]
pub fn systemctl_args(call: &SystemctlCall<'_>) -> Vec<OsString> {
    let mut args = vec![OsString::from("--user")];
    match call {
        SystemctlCall::DaemonReload => args.push("daemon-reload".into()),
        SystemctlCall::Enable(path) => {
            args.push("enable".into());
            args.push(path.as_os_str().to_owned());
        }
        SystemctlCall::Disable(unit) => {
            args.push("disable".into());
            args.push((*unit).into());
        }
        SystemctlCall::IsEnabled(unit) => {
            args.push("is-enabled".into());
            args.push((*unit).into());
        }
    }
    args
}

/// What `systemctl --user is-enabled <unit>` said, from its stdout, stderr and
/// exit status. `None` when the answer is not about the unit at all (no user
/// manager to ask).
#[must_use]
pub fn parse_is_enabled(stdout: &str, stderr: &str, success: bool) -> Option<Registration> {
    let state = stdout.lines().map(str::trim).find(|l| !l.is_empty());
    match state {
        Some("enabled" | "enabled-runtime") => Some(Registration {
            enabled: true,
            ..Registration::default()
        }),
        Some("not-found") => None,
        Some(other) => Some(Registration {
            enabled: false,
            note: Some(format!("systemd reports it `{other}`")),
            ..Registration::default()
        }),
        // Older systemd prints nothing on stdout for a unit it does not know
        // ("Failed to get unit file state for …: No such file or directory").
        None if success && stderr.trim().is_empty() => Some(Registration {
            enabled: true,
            ..Registration::default()
        }),
        None => None,
    }
}

/// `is-enabled`'s answer, classified.
fn classify_is_enabled(out: &Output) -> Result<Option<Registration>, AutostartError> {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if stdout.trim().is_empty()
        && (stderr.contains("Failed to connect") || stderr.contains("Failed to get D-Bus"))
    {
        return Err(AutostartError::Unavailable(format!(
            "no systemd user manager answers ({})",
            first_line(out)
        )));
    }
    Ok(parse_is_enabled(&stdout, &stderr, out.status.success()))
}

/// The unit's `ExecStart=` line, read back from the file for `status`.
fn exec_start_of(unit_text: &str) -> Option<String> {
    unit_text
        .lines()
        .find_map(|l| l.trim().strip_prefix("ExecStart="))
        .map(str::to_owned)
}

/// The Linux backend: a systemd user unit (§B.8.7.5).
///
/// The unit file lives in the user's configuration directory
/// (`$XDG_CONFIG_HOME/systemd/user`, else `~/.config/systemd/user`) and is
/// enabled by its absolute path, so a directory outside the manager's search
/// path still works: `systemctl enable` links it in. Nothing is started now;
/// the host starts at the next login (a host already running here would hold
/// this home's lock anyway).
///
/// With no `systemctl` binary the backend reports `Unavailable`; the XDG
/// autostart fallback of §B.8.7.5 is not implemented.
#[derive(Debug, Clone)]
pub struct SystemdUserUnit {
    systemctl: Option<PathBuf>,
    unit_dir: PathBuf,
    unit_name: String,
    spec: LaunchSpec,
}

impl SystemdUserUnit {
    /// Where `systemctl` may live; the first that exists is used. Never `PATH`.
    pub const SYSTEMCTL: [&'static str; 2] = ["/usr/bin/systemctl", "/bin/systemctl"];

    /// The backend for this user: the unit directory from `XDG_CONFIG_HOME`
    /// (when absolute) or `HOME`.
    pub fn new(spec: LaunchSpec) -> Result<Self, AutostartError> {
        let config_home = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .or_else(|| {
                std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .filter(|p| p.is_absolute())
                    .map(|h| h.join(".config"))
            })
            .ok_or_else(|| {
                AutostartError::Unavailable(
                    "neither XDG_CONFIG_HOME nor HOME names this user's configuration directory"
                        .to_owned(),
                )
            })?;
        Ok(Self::for_config_home(&config_home, UNIT_NAME, spec))
    }

    /// The backend for an explicit configuration directory and unit name
    /// (the live test uses a temporary one and a unique name).
    #[must_use]
    pub fn for_config_home(config_home: &Path, unit_name: &str, spec: LaunchSpec) -> Self {
        Self {
            systemctl: Self::SYSTEMCTL
                .iter()
                .map(PathBuf::from)
                .find(|p| p.is_file()),
            unit_dir: config_home.join("systemd").join("user"),
            unit_name: unit_name.to_owned(),
            spec,
        }
    }

    /// The unit file this backend writes.
    #[must_use]
    pub fn unit_path(&self) -> PathBuf {
        self.unit_dir.join(&self.unit_name)
    }

    fn systemctl_bin(&self) -> Result<&Path, AutostartError> {
        self.systemctl.as_deref().ok_or_else(|| {
            AutostartError::Unavailable(
                "systemd is not installed (no /usr/bin/systemctl or /bin/systemctl)".to_owned(),
            )
        })
    }

    fn run(&self, call: &SystemctlCall<'_>) -> Result<Output, AutostartError> {
        let bin = self.systemctl_bin()?;
        std::process::Command::new(bin)
            .args(systemctl_args(call))
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|e| AutostartError::Failed(format!("running {}: {e}", bin.display())))
    }

    fn run_ok(&self, call: &SystemctlCall<'_>) -> Result<(), AutostartError> {
        let out = self.run(call)?;
        if out.status.success() {
            Ok(())
        } else {
            Err(AutostartError::Failed(format!(
                "systemctl --user {:?} failed: {}",
                systemctl_args(call)
                    .get(1)
                    .map(|a| a.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                first_line(&out)
            )))
        }
    }

    /// Write the unit atomically (temp file + rename), world-readable like
    /// every unit file (it holds no secret; systemd refuses nothing for it).
    fn write_unit(&self, text: &str) -> Result<(), AutostartError> {
        let io = |e: std::io::Error| {
            AutostartError::Failed(format!("writing {}: {e}", self.unit_path().display()))
        };
        std::fs::create_dir_all(&self.unit_dir).map_err(io)?;
        let tmp = self.unit_dir.join(format!(".{}.tmp", self.unit_name));
        std::fs::write(&tmp, text).map_err(io)?;
        std::fs::rename(&tmp, self.unit_path()).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            io(e)
        })
    }
}

impl Autostart for SystemdUserUnit {
    fn preflight(&self, elevated: bool) -> Result<(), AutostartError> {
        if elevated {
            return Err(AutostartError::Unavailable(
                "there is no elevated start-at-login host: a systemd user unit runs as you"
                    .to_owned(),
            ));
        }
        self.systemctl_bin()?;
        systemd_unit_text(&self.spec)?;
        this_users_exe_location_ok(&self.spec.exe)
    }

    fn install(&self, elevated: bool) -> Result<AutostartState, AutostartError> {
        self.preflight(elevated)?;
        let text = systemd_unit_text(&self.spec)?;
        // Ask the manager first: with none answering, write nothing.
        if let Err(e @ AutostartError::Unavailable(_)) =
            classify_is_enabled(&self.run(&SystemctlCall::IsEnabled(&self.unit_name))?)
        {
            return Err(e);
        }
        self.write_unit(&text)?;
        let path = self.unit_path();
        let enabled = self
            .run_ok(&SystemctlCall::DaemonReload)
            .and_then(|()| self.run_ok(&SystemctlCall::Enable(&path)));
        if let Err(e) = enabled {
            // Leave nothing half-registered.
            let _ = self.run(&SystemctlCall::Disable(&self.unit_name));
            let _ = std::fs::remove_file(&path);
            let _ = self.run(&SystemctlCall::DaemonReload);
            return Err(e);
        }
        self.status()
    }

    fn uninstall(&self) -> Result<AutostartState, AutostartError> {
        self.systemctl_bin()?;
        let path = self.unit_path();
        let known = classify_is_enabled(&self.run(&SystemctlCall::IsEnabled(&self.unit_name))?)?;
        if known.is_some() {
            self.run_ok(&SystemctlCall::Disable(&self.unit_name))?;
        }
        match std::fs::symlink_metadata(&path) {
            Ok(_) => std::fs::remove_file(&path)
                .map_err(|e| AutostartError::Failed(format!("removing {}: {e}", path.display())))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(AutostartError::Failed(format!(
                    "reading {}: {e}",
                    path.display()
                )));
            }
        }
        self.run_ok(&SystemctlCall::DaemonReload)?;
        self.status()
    }

    fn status(&self) -> Result<AutostartState, AutostartError> {
        if let Err(AutostartError::Unavailable(why)) = self.systemctl_bin() {
            return Ok(AutostartState::Unavailable(why));
        }
        let out = self.run(&SystemctlCall::IsEnabled(&self.unit_name))?;
        let reg = match classify_is_enabled(&out) {
            Ok(reg) => reg,
            Err(AutostartError::Unavailable(why)) => return Ok(AutostartState::Unavailable(why)),
            Err(e) => return Err(e),
        };
        Ok(match reg {
            Some(mut reg) => {
                reg.command = std::fs::read_to_string(self.unit_path())
                    .ok()
                    .as_deref()
                    .and_then(exec_start_of);
                AutostartState::Registered(reg)
            }
            None => AutostartState::Absent,
        })
    }

    fn describe(&self) -> String {
        format!("systemd user unit {}", self.unit_path().display())
    }

    fn manual_removal(&self) -> String {
        format!(
            "remove it by hand with `systemctl --user disable --now {}`, then delete {}",
            self.unit_name,
            self.unit_path().display()
        )
    }
}

// ---------------------------------------------------------------------------
// Windows: a Task Scheduler at-logon task
// ---------------------------------------------------------------------------

/// The one Windows rule for a custom home (review finding SLICE-E2 E2-2), as
/// a literal both refusals below are built from.
macro_rules! windows_home_rule {
    () => {
        "on Windows, Tornect gives a `--home` or `TORNECT_HOME` directory no private \
         permissions of its own yet, so it takes one only inside your user folder, whose \
         permissions keep other accounts out, and start at login serves the default Tornect \
         directories only (review finding E2-2)"
    };
}

/// The Windows rule for a `--home` or `TORNECT_HOME` directory (review
/// finding SLICE-E2 E2-2): inside the user's profile folder only, and never
/// for the start-at-login task.
pub const WINDOWS_HOME_RULE: &str = windows_home_rule!();

/// Why the start-at-login task refuses a custom home on Windows: the rule of
/// [`WINDOWS_HOME_RULE`], word for word.
pub const WINDOWS_CUSTOM_HOME_REFUSAL: &str = concat!(
    windows_home_rule!(),
    "; run `tornect service install` without it"
);

/// Whether Tornect may keep its state in `home` on Windows (review finding
/// E2-2): only inside `profile`, the user's profile folder as the OS names it
/// (`FOLDERID_Profile`), or in it. A profile the OS does not name is not
/// guessed. `home` must be absolute; `..` and verbatim (`\\?\`) paths are
/// refused rather than resolved.
pub fn windows_home_ok(home: &str, profile: Option<&str>) -> Result<(), String> {
    if let Some(profile) = profile.filter(|p| !p.is_empty()) {
        let bare = |s: &str| s.replace('/', "\\").trim_end_matches('\\').to_lowercase();
        if bare(home) == bare(profile) || location_under(home, &[profile.to_owned()]) {
            return Ok(());
        }
        return Err(format!(
            "{home} is not inside your user folder ({profile}): {WINDOWS_HOME_RULE}; use a \
             directory inside your user folder, or none"
        ));
    }
    Err(format!(
        "{home} cannot be checked, because Windows did not name your user folder: \
         {WINDOWS_HOME_RULE}"
    ))
}

/// XML-escape text for an element body.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// A Windows executable path the task can run, quoted for its command field.
///
/// Refused: a relative path, a control character, `"` (not a legal file-name
/// character, so only a hostile string holds one) and `%` (the Task Scheduler
/// expands `%VAR%` in the command field, and there is no escape for it).
pub fn task_command(exe: &str) -> Result<String, AutostartError> {
    let bytes = exe.as_bytes();
    let drive = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/');
    let unc = exe.starts_with("\\\\") && !exe.starts_with("\\\\?\\");
    if !(drive || unc) {
        return Err(AutostartError::Unquotable(format!(
            "{exe:?} is not an absolute Windows path"
        )));
    }
    if let Some(c) = exe
        .chars()
        .find(|c| c.is_control() || *c == '"' || *c == '%')
    {
        return Err(AutostartError::Unquotable(format!(
            "{exe:?} contains {c:?}, which the Task Scheduler cannot take in a command"
        )));
    }
    Ok(format!("\"{exe}\""))
}

/// A string SID (`S-1-5-21-…`), checked before it goes into the task XML.
fn checked_sid(sid: &str) -> Result<&str, AutostartError> {
    let ok = sid.starts_with("S-1-")
        && sid.len() <= 184
        && sid[4..]
            .split('-')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    if ok {
        Ok(sid)
    } else {
        Err(AutostartError::Failed(format!("{sid:?} is not a user SID")))
    }
}

/// The task definition `schtasks /Create /XML` registers.
///
/// Why XML rather than `/SC ONLOGON /TR … /RL …`: a task made from those
/// switches keeps the Task Scheduler's stock settings, which a host must not
/// have — stopped after 72 hours, started only on AC power, stopped when the
/// laptop is unplugged — and a bare `/SC ONLOGON` trigger fires at *any*
/// user's logon, which was reported to fail with "Access is denied" from a
/// standard account. Here the logon trigger and the principal name this user
/// (by SID), so a standard account should register it without elevation
/// (NEEDS-DEVICE); `RunLevel` is `LeastPrivilege` (`/RL LIMITED`) or, for
/// the whole-host elevated task of earlier versions (refused since r7, built
/// here only for the tests), `HighestAvailable` (`/RL HIGHEST`); there is no time limit,
/// the battery conditions are off, a second instance is not started, the
/// priority is normal (the default, 7, is below normal), and only the plain
/// task may be started on demand (slice-F F1-5).
///
/// The task runs the app in the background, `tornect.exe --background`
/// ([`LaunchSpec::app_args`]; §B.1.1): the window host, minimised, with its
/// sharing indicator and banner. The task itself is not hidden either.
pub fn task_xml(
    spec: &LaunchSpec,
    user_sid: &str,
    elevated: bool,
) -> Result<String, AutostartError> {
    if spec.home.is_some() {
        return Err(AutostartError::Unavailable(
            WINDOWS_CUSTOM_HOME_REFUSAL.to_owned(),
        ));
    }
    let exe = spec.exe.to_str().ok_or_else(|| {
        AutostartError::Unquotable(format!("{} is not valid Unicode", spec.exe.display()))
    })?;
    let command = xml_escape(&task_command(exe)?);
    // A custom home was refused above, so this is `--background`.
    let arguments = xml_escape(
        &spec
            .app_args()
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" "),
    );
    let sid = xml_escape(checked_sid(user_sid)?);
    let run_level = if elevated {
        "HighestAvailable"
    } else {
        "LeastPrivilege"
    };
    // Slice-F F1-5: nothing may start the elevated host on demand (`schtasks
    // /Run`), should the task's security descriptor let this user's filtered
    // token run it; only the logon trigger does.
    let on_demand = !elevated;
    let mut xml = String::new();
    // `write!` into a String cannot fail.
    let _ = write!(
        xml,
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n\
<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n\
  <RegistrationInfo>\r\n\
    <Description>Tornect: start the Tornect window minimised at logon. Written by `tornect service install`; `tornect service uninstall` removes it.</Description>\r\n\
  </RegistrationInfo>\r\n\
  <Triggers>\r\n\
    <LogonTrigger>\r\n\
      <Enabled>true</Enabled>\r\n\
      <UserId>{sid}</UserId>\r\n\
    </LogonTrigger>\r\n\
  </Triggers>\r\n\
  <Principals>\r\n\
    <Principal id=\"Author\">\r\n\
      <UserId>{sid}</UserId>\r\n\
      <LogonType>InteractiveToken</LogonType>\r\n\
      <RunLevel>{run_level}</RunLevel>\r\n\
    </Principal>\r\n\
  </Principals>\r\n\
  <Settings>\r\n\
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\r\n\
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\r\n\
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\r\n\
    <AllowHardTerminate>true</AllowHardTerminate>\r\n\
    <StartWhenAvailable>false</StartWhenAvailable>\r\n\
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\r\n\
    <IdleSettings>\r\n\
      <StopOnIdleEnd>false</StopOnIdleEnd>\r\n\
      <RestartOnIdle>false</RestartOnIdle>\r\n\
    </IdleSettings>\r\n\
    <AllowStartOnDemand>{on_demand}</AllowStartOnDemand>\r\n\
    <Enabled>true</Enabled>\r\n\
    <Hidden>false</Hidden>\r\n\
    <RunOnlyIfIdle>false</RunOnlyIfIdle>\r\n\
    <WakeToRun>false</WakeToRun>\r\n\
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\r\n\
    <Priority>5</Priority>\r\n\
  </Settings>\r\n\
  <Actions Context=\"Author\">\r\n\
    <Exec>\r\n\
      <Command>{command}</Command>\r\n\
      <Arguments>{arguments}</Arguments>\r\n\
    </Exec>\r\n\
  </Actions>\r\n\
</Task>\r\n"
    );
    Ok(xml)
}

/// The task XML as the file `schtasks /XML` reads: UTF-16LE with a BOM.
#[must_use]
pub fn task_xml_file_bytes(xml: &str) -> Vec<u8> {
    let mut bytes = vec![0xFF, 0xFE];
    for unit in xml.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes
}

/// One `schtasks.exe` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchtasksCall<'a> {
    /// `/Create /F /TN Tornect /XML <file>` (`/F`: replace an existing task).
    Create(&'a str),
    /// `/Delete /TN Tornect /F`.
    Delete,
    /// `/Query /TN Tornect /XML`: the definition, which says whether the task
    /// is enabled and elevated (the `/FO LIST` view says neither reliably).
    Query,
}

/// The argument vector for `call`.
#[must_use]
pub fn schtasks_args(call: &SchtasksCall<'_>) -> Vec<String> {
    let v = |a: &[&str]| a.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
    match call {
        SchtasksCall::Create(xml) => v(&["/Create", "/F", "/TN", TASK_NAME, "/XML", xml]),
        SchtasksCall::Delete => v(&["/Delete", "/TN", TASK_NAME, "/F"]),
        SchtasksCall::Query => v(&["/Query", "/TN", TASK_NAME, "/XML"]),
    }
}

/// Quote arguments into one Windows command line (`CommandLineToArgvW` rules:
/// an argument with a space, a tab or a quote goes in quotes; backslashes before
/// a quote are doubled). For `ShellExecuteExW`, which takes a single string.
#[must_use]
pub fn windows_command_line(args: &[String]) -> String {
    let mut line = String::new();
    for (i, arg) in args.iter().enumerate() {
        if i > 0 {
            line.push(' ');
        }
        if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
            line.push_str(arg);
            continue;
        }
        line.push('"');
        let mut backslashes = 0usize;
        for c in arg.chars() {
            match c {
                '\\' => backslashes += 1,
                '"' => {
                    line.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                    line.push('"');
                    backslashes = 0;
                }
                c => {
                    line.extend(std::iter::repeat_n('\\', backslashes));
                    line.push(c);
                    backslashes = 0;
                }
            }
        }
        line.extend(std::iter::repeat_n('\\', backslashes * 2));
        line.push('"');
    }
    line
}

/// The body of the first `<tag>…</tag>` (or `<tag attr…>…</tag>`) in `xml`.
fn element<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}");
    let mut from = 0;
    while let Some(i) = xml[from..].find(&open) {
        let start = from + i + open.len();
        let rest = &xml[start..];
        // `<Enabled>` must not match `<EnabledX>`.
        match rest.chars().next() {
            Some('>') | Some(' ') | Some('\t') | Some('\r') | Some('\n') => {}
            Some('/') => return Some(""),
            _ => {
                from = start;
                continue;
            }
        }
        let body_start = start + rest.find('>')? + 1;
        let close = format!("</{tag}>");
        let end = xml[body_start..].find(&close)? + body_start;
        return Some(&xml[body_start..end]);
    }
    None
}

/// What the file the Task Scheduler keeps a root-folder task in
/// (`<system directory>\Tasks\Tornect`) says about the task: the definite
/// not-found test of slice-F F1-1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskFile {
    /// `NotFound`: there is no task by that name.
    Missing,
    /// It exists: read, or refused (`PermissionDenied` proves it is there).
    Present,
    /// Any other answer: nothing is known.
    Unknown(String),
}

impl TaskFile {
    /// Classify a lookup of the file (`symlink_metadata`).
    #[must_use]
    pub fn from_lookup(lookup: std::io::Result<()>) -> Self {
        match lookup {
            Ok(()) => Self::Present,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::Missing,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Self::Present,
            Err(e) => Self::Unknown(e.to_string()),
        }
    }
}

/// What `schtasks /Query /TN Tornect /XML` answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskQuery {
    /// Its stdout, decoded.
    pub text: String,
    /// Its exit status.
    pub success: bool,
    /// Its first line that says something (stderr first), for messages.
    pub message: String,
}

/// The Task Scheduler as the Windows backend drives it. A seam, so that what
/// the backend decides is tested on every OS.
pub trait TaskScheduling {
    /// `schtasks /Query /TN Tornect /XML`.
    fn query(&self) -> Result<TaskQuery, AutostartError>;
    /// The definite not-found test.
    fn task_file(&self) -> TaskFile;
    /// `call`, through the UAC prompt when `elevated`.
    fn change(&self, call: &SchtasksCall<'_>, elevated: bool) -> Result<(), AutostartError>;
    /// Whether this account is an administrator (a filtered administrator
    /// token counts).
    fn administrator(&self) -> std::io::Result<bool>;
    /// Whether `principal`, a task's `<UserId>` as the Task Scheduler prints
    /// it (a SID or an account name), is this account.
    fn is_this_account(&self, principal: &str) -> bool;
}

/// The manual step for a task Tornect could not remove or cannot see.
pub const MANUAL_TASK_DELETE: &str =
    "remove it in an administrator console with `schtasks /Delete /TN Tornect /F`";

/// What is said of a task that exists but this account cannot read.
const UNREADABLE_TASK: &str = "a task \\Tornect exists that this account cannot read (installed \
     from an administrator prompt?)";

/// A query's answer and the file test, as a state (slice-F F1-1).
///
/// A failed query never means "not registered" by itself: `schtasks` fails
/// the same way for a task this account may not read (one registered from an
/// administrator prompt) as for a missing one, and its message is localized.
/// `Absent` needs the definite not-found of [`TaskFile::Missing`] as well. A
/// task whose file exists but whose definition cannot be read is an
/// [`Registration::unreadable`] registration; anything else is an error.
pub fn classify_task_query(
    query: &TaskQuery,
    file: &TaskFile,
) -> Result<AutostartState, AutostartError> {
    if query.success {
        return parse_task_definition(&query.text)
            .map(AutostartState::Registered)
            .ok_or_else(|| {
                AutostartError::Failed(format!(
                    "could not read the start-at-login task: schtasks.exe printed no task \
                     definition ({})",
                    query.text.lines().next().unwrap_or("no output").trim()
                ))
            });
    }
    match file {
        TaskFile::Missing => Ok(AutostartState::Absent),
        TaskFile::Present => Ok(AutostartState::Registered(Registration {
            note: Some(UNREADABLE_TASK.to_owned()),
            unreadable: true,
            ..Registration::default()
        })),
        TaskFile::Unknown(why) => Err(AutostartError::Failed(format!(
            "could not read the start-at-login task: {}; and its file: {why}",
            query.message
        ))),
    }
}

/// Why the whole-host elevated task (M1-53) is refused since r7 (§B.8.7.5,
/// decision M1-57; the operator's ruling of 2026-09-28): administrator access
/// is given per session by the administrator helper, and nothing
/// network-facing runs elevated.
pub const ELEVATED_TASK_GONE: &str = "the elevated start-at-login task is gone: administrator \
     access is now given per session (\"Allow as administrator\"), and nothing that talks to the \
     network runs elevated; run `tornect service install` for the normal task";

/// Migration (r7, §B.8.7.5; review DA-3, DA-13): a whole-host elevated task
/// of an earlier version (M1-53) — or one this account cannot read, which may
/// be one — is removed through the UAC prompt (F1-1's elevated delete) and
/// its absence confirmed. `Ok(true)`: one was removed; `Ok(false)`: there was
/// none. A cancelled prompt or a failed removal is an error: the plain task
/// is never registered beside it.
pub fn migrate_elevated_task(ts: &dyn TaskScheduling) -> Result<bool, AutostartError> {
    match task_status(ts)? {
        AutostartState::Registered(r) if r.elevated || r.unreadable => {}
        _ => return Ok(false),
    }
    ts.change(&SchtasksCall::Delete, true)?;
    match task_status(ts) {
        Ok(AutostartState::Absent) => Ok(true),
        Ok(_) => Err(AutostartError::Failed(format!(
            "the elevated task of an earlier version is still registered after the delete; \
             {MANUAL_TASK_DELETE}"
        ))),
        Err(e) => Err(AutostartError::Failed(format!(
            "could not confirm that the elevated task of an earlier version is gone ({e}); \
             {MANUAL_TASK_DELETE}"
        ))),
    }
}

/// Why a standard account may not register the elevated task (decided
/// 2026-09-24, slice-F review §3.2).
pub const ELEVATED_NEEDS_ADMINISTRATOR: &str = "an elevated task needs an administrator account, \
     and this is a standard account: approved with another account's password, the elevated task \
     would belong to that account, and you could neither read nor remove it; run `tornect \
     service install` for the normal task";

/// Whether this account may register the elevated task: an administrator
/// only, its filtered (not elevated) token included (decided 2026-09-24,
/// slice-F review §3.2). A standard account would need another account's password at
/// the UAC prompt, which makes that account the task's owner: the task could
/// then neither be read nor removed by the account it runs for. A check that
/// fails refuses.
pub fn elevated_task_account_ok(ts: &dyn TaskScheduling) -> Result<(), AutostartError> {
    match ts.administrator() {
        Ok(true) => Ok(()),
        Ok(false) => Err(AutostartError::Unavailable(
            ELEVATED_NEEDS_ADMINISTRATOR.to_owned(),
        )),
        Err(e) => Err(AutostartError::Unavailable(format!(
            "could not tell whether this account is an administrator ({e}), and an elevated \
             task needs one"
        ))),
    }
}

/// Who a task definition runs as, at which run level, and what: the fields
/// [`task_install`] compares after registering (slice-F F1-2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TaskFacts {
    /// The principal's `<UserId>`: a SID, or an account name.
    pub principal: Option<String>,
    /// The principal's `<RunLevel>`; absent means `LeastPrivilege`.
    pub run_level: Option<String>,
    /// The action's `<Command>`, unescaped.
    pub command: Option<String>,
    /// The action's `<Arguments>`, unescaped.
    pub arguments: Option<String>,
    /// How many actions `<Actions>` holds, of any kind (review N-3: the
    /// fields above are the first `<Exec>`'s).
    pub actions: usize,
    /// The definition holds only elements and text after one XML declaration
    /// at its start (review P2-I2): no comment, CDATA section, DOCTYPE or
    /// other processing instruction, which the element count and `element`
    /// read wrong when one holds `>`.
    pub only_elements: bool,
}

/// Whether `xml` holds only elements and text after one XML declaration at
/// its start (`<?xml` then white space, no `<` or `>`, then `?>`; what
/// `schtasks /Query /XML` prints first).
fn only_elements(xml: &str) -> bool {
    let body = xml.trim_start();
    let body = match body.strip_prefix("<?xml") {
        Some(rest) if rest.starts_with(|c: char| c.is_ascii_whitespace()) => {
            match rest.find("?>") {
                Some(end) if !rest[..end].contains(['<', '>']) => &rest[end + 2..],
                _ => return false,
            }
        }
        Some(_) => return false,
        None => body,
    };
    !body.contains("<!") && !body.contains("<?")
}

/// The number of elements directly inside `body`, an element's content.
fn child_elements(body: &str) -> usize {
    let (mut depth, mut count, mut rest) = (0usize, 0usize, body);
    while let Some(open) = rest.find('<') {
        rest = &rest[open + 1..];
        let end = rest.find('>').unwrap_or(rest.len());
        let tag = &rest[..end];
        if tag.starts_with('/') {
            depth = depth.saturating_sub(1);
        } else if !tag.starts_with('!') && !tag.starts_with('?') {
            if depth == 0 {
                count += 1;
            }
            if !tag.ends_with('/') {
                depth += 1;
            }
        }
        rest = &rest[end..];
    }
    count
}

/// The [`TaskFacts`] of a task definition.
#[must_use]
pub fn task_facts(xml: &str) -> TaskFacts {
    let principal = element(xml, "Principals").and_then(|p| element(p, "Principal"));
    let exec = element(xml, "Exec");
    let text = |v: Option<&str>| v.map(|v| xml_unescape(v.trim())).filter(|v| !v.is_empty());
    TaskFacts {
        principal: text(principal.and_then(|p| element(p, "UserId"))),
        run_level: text(principal.and_then(|p| element(p, "RunLevel"))),
        command: text(exec.and_then(|e| element(e, "Command"))),
        arguments: text(exec.and_then(|e| element(e, "Arguments"))),
        actions: element(xml, "Actions").map_or(0, child_elements),
        only_elements: only_elements(xml),
    }
}

/// Whether the task the Task Scheduler holds (`registered`) is the one
/// Tornect wrote (`written`): only elements and text after the XML
/// declaration (review P2-I2), exactly one action in each (review N-3: a
/// second one would run too), run as this account (`is_this_account`, which
/// also takes the name form the scheduler may print), at the same run level,
/// the same command (case-folded: a Windows path) and the same arguments. `Err` says what differs (slice-F F1-2: the definition file sat
/// on disk between Tornect writing it and `schtasks` reading it).
pub fn registered_matches(
    written: &TaskFacts,
    registered: &TaskFacts,
    is_this_account: &dyn Fn(&str) -> bool,
) -> Result<(), String> {
    let level = |f: &TaskFacts| {
        f.run_level
            .clone()
            .unwrap_or_else(|| "LeastPrivilege".into())
    };
    let mut differs = Vec::new();
    if !written.only_elements || !registered.only_elements {
        differs.push(
            "it holds a comment, CDATA section or processing instruction, which could hide \
             markup"
                .to_owned(),
        );
    }
    if written.actions != 1 || registered.actions != 1 {
        differs.push(format!("it holds {} actions, not one", registered.actions));
    }
    match registered.principal.as_deref() {
        Some(p) if is_this_account(p) => {}
        Some(p) => differs.push(format!("it runs as {p}, not as you")),
        None => differs.push("it names no account to run as".to_owned()),
    }
    if level(written) != level(registered) {
        differs.push(format!(
            "its run level is {}, not {}",
            level(registered),
            level(written)
        ));
    }
    let same_command = match (&written.command, &registered.command) {
        (Some(w), Some(r)) => w.eq_ignore_ascii_case(r),
        _ => false,
    };
    if !same_command || written.arguments != registered.arguments {
        differs.push(format!(
            "it runs {} {}",
            registered.command.as_deref().unwrap_or("nothing"),
            registered.arguments.as_deref().unwrap_or("")
        ));
    }
    if differs.is_empty() {
        Ok(())
    } else {
        Err(differs.join("; "))
    }
}

/// Remove a task that is not the one written, elevated when needed, and say
/// what happened.
fn remove_mismatched(ts: &dyn TaskScheduling, what: &str, elevated: bool) -> AutostartError {
    match ts.change(&SchtasksCall::Delete, elevated) {
        Ok(()) => AutostartError::Failed(format!(
            "the task registered is not the one Tornect wrote ({what}), so it was removed; \
             run `tornect service install` again"
        )),
        Err(e) => AutostartError::Failed(format!(
            "the task registered is not the one Tornect wrote ({what}), and removing it failed \
             ({e}); {MANUAL_TASK_DELETE}"
        )),
    }
}

/// [`Autostart::status`] of the Task Scheduler backend.
pub fn task_status(ts: &dyn TaskScheduling) -> Result<AutostartState, AutostartError> {
    let query = ts.query()?;
    classify_task_query(&query, &ts.task_file())
}

/// [`Autostart::install`] of the Task Scheduler backend, once the task
/// definition `written` is on disk at `xml_path`. What the Task Scheduler
/// then holds is read back and compared with `written`
/// ([`registered_matches`]); a task that differs is removed and the install
/// fails (slice-F F1-2).
///
/// After a registration `schtasks` reported done, the answer is never
/// "nothing starts at login": a task this account cannot read back (an
/// administrator's token registered it) is reported as registered and
/// unreadable (slice-F F1-1). The elevated task is refused to a standard
/// account before any UAC prompt ([`elevated_task_account_ok`]).
pub fn task_install(
    ts: &dyn TaskScheduling,
    xml_path: &str,
    written: &str,
    elevated: bool,
) -> Result<AutostartState, AutostartError> {
    if elevated {
        elevated_task_account_ok(ts)?;
    }
    ts.change(&SchtasksCall::Create(xml_path), elevated)?;
    let why = match ts.query() {
        Ok(query) => match classify_task_query(&query, &ts.task_file()) {
            Ok(AutostartState::Registered(r)) if !r.unreadable => {
                let is_this_account = |p: &str| ts.is_this_account(p);
                if let Err(what) = registered_matches(
                    &task_facts(written),
                    &task_facts(&query.text),
                    &is_this_account,
                ) {
                    return Err(remove_mismatched(ts, &what, elevated || r.elevated));
                }
                return Ok(AutostartState::Registered(r));
            }
            Ok(AutostartState::Unavailable(why)) => return Err(AutostartError::Unavailable(why)),
            Ok(_) => String::new(),
            Err(e) => format!(" ({e})"),
        },
        Err(e) => format!(" ({e})"),
    };
    Ok(AutostartState::Registered(Registration {
        enabled: true,
        elevated,
        command: None,
        note: Some(format!(
            "registered; this account cannot read it back, so it was not compared with what \
             Tornect wrote{why}"
        )),
        unreadable: true,
    }))
}

/// [`Autostart::uninstall`] of the Task Scheduler backend (slice-F F1-1).
///
/// An elevated or unreadable task is deleted through the UAC prompt: the
/// plain delete cannot remove an administrator's task. The removal is then
/// confirmed with the definite not-found test, and only that is reported as
/// removed; anything else fails with the manual step. A cancelled prompt
/// stays [`AutostartError::Cancelled`].
pub fn task_uninstall(ts: &dyn TaskScheduling) -> Result<AutostartState, AutostartError> {
    let manual = |e: AutostartError| match e {
        AutostartError::Failed(m) => AutostartError::Failed(format!("{m}; {MANUAL_TASK_DELETE}")),
        other => other,
    };
    let elevated = match task_status(ts).map_err(manual)? {
        AutostartState::Absent => return Ok(AutostartState::Absent),
        AutostartState::Unavailable(why) => return Err(AutostartError::Unavailable(why)),
        AutostartState::Registered(r) => r.elevated || r.unreadable,
    };
    ts.change(&SchtasksCall::Delete, elevated).map_err(manual)?;
    match task_status(ts) {
        Ok(AutostartState::Absent) => Ok(AutostartState::Absent),
        Ok(AutostartState::Registered(_)) => Err(AutostartError::Failed(format!(
            "the task \\{TASK_NAME} is still registered after the delete; {MANUAL_TASK_DELETE}"
        ))),
        Ok(AutostartState::Unavailable(why)) => Err(AutostartError::Failed(format!(
            "could not confirm that the task \\{TASK_NAME} is gone ({why}); \
             {MANUAL_TASK_DELETE}"
        ))),
        Err(e) => Err(AutostartError::Failed(format!(
            "could not confirm that the task \\{TASK_NAME} is gone ({e}); {MANUAL_TASK_DELETE}"
        ))),
    }
}

/// The task definition `schtasks /Query /TN Tornect /XML` printed, as a
/// registration; `None` when the output holds no `<Task>`.
#[must_use]
pub fn parse_task_definition(output: &str) -> Option<Registration> {
    element(output, "Task")?;
    let is_true = |v: Option<&str>| !matches!(v.map(str::trim), Some("false"));
    let settings = element(output, "Settings").unwrap_or("");
    let trigger = element(output, "LogonTrigger");
    let task_enabled = is_true(element(settings, "Enabled"));
    let trigger_enabled = trigger.is_some_and(|t| is_true(element(t, "Enabled")));
    let elevated = element(output, "RunLevel").map(str::trim) == Some("HighestAvailable");
    let command = element(output, "Exec").and_then(|exec| {
        let cmd = element(exec, "Command").map(|c| xml_unescape(c.trim()))?;
        Some(
            match element(exec, "Arguments").map(|a| xml_unescape(a.trim())) {
                Some(args) if !args.is_empty() => format!("{cmd} {args}"),
                _ => cmd,
            },
        )
    });
    let note = if !task_enabled {
        Some("the task is disabled".to_owned())
    } else if trigger.is_none() {
        Some("the task has no logon trigger".to_owned())
    } else if !trigger_enabled {
        Some("its logon trigger is disabled".to_owned())
    } else {
        None
    };
    Some(Registration {
        enabled: note.is_none(),
        elevated,
        command,
        note,
        unreadable: false,
    })
}

/// Whether the Windows path `exe` lies under one of `folders`: a case-folded
/// prefix test with a separator appended, `..` refused.
#[must_use]
pub fn location_under(exe: &str, folders: &[String]) -> bool {
    let norm = |s: &str| s.replace('/', "\\").to_lowercase();
    let exe = norm(exe);
    folders.iter().filter(|p| !p.is_empty()).any(|dir| {
        let mut dir = norm(dir);
        if !dir.ends_with('\\') {
            dir.push('\\');
        }
        exe.starts_with(&dir) && !exe[dir.len()..].split('\\').any(|c| c == "..")
    })
}

/// The Windows backend: a Task Scheduler task with a logon trigger for this
/// user (§B.8.7.5).
#[cfg(windows)]
#[derive(Debug, Clone)]
pub struct TaskScheduler {
    schtasks: PathBuf,
    /// Where the Task Scheduler keeps the task's definition.
    task_file: PathBuf,
    spec: LaunchSpec,
}

#[cfg(windows)]
impl TaskScheduler {
    /// The backend, with `schtasks.exe` from the system directory.
    pub fn new(spec: LaunchSpec) -> Result<Self, AutostartError> {
        let system = crate::win::system_directory()
            .map_err(|e| AutostartError::Unavailable(format!("no system directory: {e}")))?;
        Ok(Self {
            schtasks: system.join("schtasks.exe"),
            task_file: system.join("Tasks").join(TASK_NAME),
            spec,
        })
    }

    fn exe_str(&self) -> Result<&str, AutostartError> {
        self.spec.exe.to_str().ok_or_else(|| {
            AutostartError::Unquotable(format!("{} is not valid Unicode", self.spec.exe.display()))
        })
    }

    fn xml(&self, elevated: bool) -> Result<String, AutostartError> {
        let sid = crate::win::current_user_sid()
            .map_err(|e| AutostartError::Failed(format!("reading this user's SID: {e}")))?;
        let folder = |id| {
            crate::win::known_folder(id)
                .ok()
                .and_then(|p| p.to_str().map(str::to_owned))
        };
        windows_exe_location_ok(
            self.exe_str()?,
            elevated,
            folder(crate::win::KnownFolder::Profile).as_deref(),
            folder(crate::win::KnownFolder::ProgramFiles).as_deref(),
        )?;
        task_xml(&self.spec, &sid, elevated)
    }

    fn run(&self, call: &SchtasksCall<'_>) -> Result<Output, AutostartError> {
        std::process::Command::new(&self.schtasks)
            .args(schtasks_args(call))
            .stdin(std::process::Stdio::null())
            .output()
            .map_err(|e| {
                AutostartError::Failed(format!("running {}: {e}", self.schtasks.display()))
            })
    }
}

#[cfg(windows)]
impl TaskScheduling for TaskScheduler {
    fn query(&self) -> Result<TaskQuery, AutostartError> {
        let out = self.run(&SchtasksCall::Query)?;
        Ok(TaskQuery {
            text: decode_console_output(&out.stdout),
            success: out.status.success(),
            message: first_line(&out),
        })
    }

    fn task_file(&self) -> TaskFile {
        TaskFile::from_lookup(std::fs::symlink_metadata(&self.task_file).map(drop))
    }

    fn administrator(&self) -> std::io::Result<bool> {
        crate::win::is_administrator()
    }

    fn is_this_account(&self, principal: &str) -> bool {
        let Ok(ours) = crate::win::current_user_sid() else {
            return false;
        };
        principal.trim().eq_ignore_ascii_case(&ours)
            || crate::win::sid_of_account_name(principal.trim())
                .is_ok_and(|theirs| theirs.eq_ignore_ascii_case(&ours))
    }

    fn change(&self, call: &SchtasksCall<'_>, elevated: bool) -> Result<(), AutostartError> {
        if elevated {
            let line = windows_command_line(&schtasks_args(call));
            match crate::win::run_elevated(&self.schtasks, &line) {
                Ok(0) => Ok(()),
                Ok(code) => Err(AutostartError::Failed(format!(
                    "the elevated schtasks.exe exited with {code}"
                ))),
                Err(crate::win::ElevateError::Cancelled) => Err(AutostartError::Cancelled),
                Err(crate::win::ElevateError::Failed(m)) => Err(AutostartError::Failed(m)),
            }
        } else {
            let out = self.run(call)?;
            if out.status.success() {
                Ok(())
            } else {
                Err(AutostartError::Failed(format!(
                    "schtasks.exe failed: {}",
                    first_line(&out)
                )))
            }
        }
    }
}

#[cfg(windows)]
impl Autostart for TaskScheduler {
    fn preflight(&self, elevated: bool) -> Result<(), AutostartError> {
        if !self.schtasks.is_file() {
            return Err(AutostartError::Unavailable(format!(
                "{} is missing",
                self.schtasks.display()
            )));
        }
        // r7: the whole-host elevated task is gone (the administrator
        // helper replaces it), refused before any dialog.
        if elevated {
            return Err(AutostartError::Unavailable(ELEVATED_TASK_GONE.to_owned()));
        }
        self.xml(elevated).map(drop)
    }

    fn install(&self, elevated: bool) -> Result<AutostartState, AutostartError> {
        self.preflight(elevated)?;
        // Migration: an earlier version's elevated task goes first, through
        // the UAC prompt; the two are never registered together.
        if migrate_elevated_task(self)? {
            tracing::info!("removed the elevated start-at-login task of an earlier version");
        }
        let xml = self.xml(elevated)?;
        // Slice-F F1-2: in this user's own local application data folder,
        // from the OS, never `%TEMP%`, which the environment can point at a
        // folder other accounts can write.
        let dir = crate::win::known_folder(crate::win::KnownFolder::LocalAppData)
            .map_err(|e| {
                AutostartError::Failed(format!("finding your local application data folder: {e}"))
            })?
            .join("Tornect");
        std::fs::create_dir_all(&dir)
            .map_err(|e| AutostartError::Failed(format!("creating {}: {e}", dir.display())))?;
        let file = crate::win::TempFile::write(
            &dir,
            "tornect-autostart",
            ".xml",
            &task_xml_file_bytes(&xml),
        )
        .map_err(|e| AutostartError::Failed(format!("writing the task definition: {e}")))?;
        let path = file.path().to_str().ok_or_else(|| {
            AutostartError::Failed("the task definition's path is not valid Unicode".to_owned())
        })?;
        let state = task_install(self, path, &xml, elevated);
        drop(file);
        state
    }

    fn uninstall(&self) -> Result<AutostartState, AutostartError> {
        task_uninstall(self)
    }

    fn status(&self) -> Result<AutostartState, AutostartError> {
        if !self.schtasks.is_file() {
            return Ok(AutostartState::Unavailable(format!(
                "{} is missing",
                self.schtasks.display()
            )));
        }
        task_status(self)
    }

    fn describe(&self) -> String {
        format!("Task Scheduler task \\{TASK_NAME}")
    }

    fn manual_removal(&self) -> String {
        MANUAL_TASK_DELETE.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(exe: &str, home: Option<&str>) -> LaunchSpec {
        LaunchSpec {
            exe: PathBuf::from(exe),
            home: home.map(PathBuf::from),
        }
    }

    #[test]
    fn the_launch_spec_runs_the_host_with_its_home() {
        assert_eq!(
            spec("/usr/bin/tornect", None).args(),
            vec![OsString::from("host")]
        );
        assert_eq!(
            spec("/usr/bin/tornect", Some("/srv/t")).args(),
            ["--home", "/srv/t", "host"].map(OsString::from).to_vec()
        );
    }

    /// Table: every item quoted; the characters systemd would reinterpret are
    /// escaped; what cannot be written safely is refused.
    #[test]
    fn systemd_items_are_quoted_or_refused() {
        let q = |s: &str| systemd_quote(std::ffi::OsStr::new(s));
        for (input, want) in [
            ("host", "\"host\""),
            ("/opt/Tornect App/tornect", "\"/opt/Tornect App/tornect\""),
            ("/a\\b", "\"/a\\\\b\""),
            ("/a\"b", "\"/a\\\"b\""),
            ("/100%/t", "\"/100%%/t\""),
            ("/$HOME/t", "\"/$$HOME/t\""),
            ("/x;y", "\"/x;y\""),
            ("/ünï/t", "\"/ünï/t\""),
        ] {
            assert_eq!(q(input).unwrap(), want, "{input:?}");
        }
        for bad in ["/a\nb", "/a\tb", "/a\u{7f}b", "/a\rExecStartPre=/bin/sh"] {
            assert!(
                matches!(q(bad), Err(AutostartError::Unquotable(_))),
                "{bad:?} must be refused"
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt as _;
            assert!(matches!(
                systemd_quote(std::ffi::OsStr::from_bytes(b"/a\xffb")),
                Err(AutostartError::Unquotable(_))
            ));
        }
    }

    #[test]
    fn the_unit_file_runs_the_host_after_the_graphical_session() {
        let text = systemd_unit_text(&spec("/opt/Tornect App/tornect", None)).unwrap();
        assert!(
            text.contains("\nExecStart=\"/opt/Tornect App/tornect\" \"host\"\n"),
            "{text}"
        );
        for line in [
            "PartOf=graphical-session.target",
            "After=graphical-session.target",
            "WantedBy=graphical-session.target",
            "KillSignal=SIGINT",
            "Restart=on-abnormal",
        ] {
            assert!(text.lines().any(|l| l == line), "missing {line}:\n{text}");
        }
        let custom =
            systemd_unit_text(&spec("/usr/bin/tornect", Some("/srv/tornect home"))).unwrap();
        assert!(
            custom.contains(
                "ExecStart=\"/usr/bin/tornect\" \"--home\" \"/srv/tornect home\" \"host\""
            ),
            "{custom}"
        );
        assert_eq!(
            exec_start_of(&custom).as_deref(),
            Some("\"/usr/bin/tornect\" \"--home\" \"/srv/tornect home\" \"host\"")
        );
        // Relative paths would resolve against whatever directory the user
        // manager starts in.
        assert!(systemd_unit_text(&spec("tornect", None)).is_err());
        assert!(systemd_unit_text(&spec("/usr/bin/tornect", Some("rel/home"))).is_err());
    }

    /// What a refusal tells the user to do by hand (F2-4's side effect):
    /// the unit's name for `systemctl` and the file to delete.
    #[test]
    fn the_manual_removal_names_the_unit_and_its_file() {
        let unit = SystemdUserUnit::for_config_home(
            Path::new("/home/u/.config"),
            UNIT_NAME,
            spec("/usr/bin/tornect", None),
        );
        assert_eq!(
            unit.manual_removal(),
            "remove it by hand with `systemctl --user disable --now tornect-host.service`, then \
             delete /home/u/.config/systemd/user/tornect-host.service"
        );
        assert!(MANUAL_TASK_DELETE.contains("schtasks /Delete /TN Tornect /F"));
    }

    #[test]
    fn systemctl_argument_vectors() {
        let path = Path::new("/home/u/.config/systemd/user/tornect-host.service");
        for (call, want) in [
            (SystemctlCall::DaemonReload, vec!["--user", "daemon-reload"]),
            (
                SystemctlCall::Enable(path),
                vec![
                    "--user",
                    "enable",
                    "/home/u/.config/systemd/user/tornect-host.service",
                ],
            ),
            (
                SystemctlCall::Disable(UNIT_NAME),
                vec!["--user", "disable", "tornect-host.service"],
            ),
            (
                SystemctlCall::IsEnabled(UNIT_NAME),
                vec!["--user", "is-enabled", "tornect-host.service"],
            ),
        ] {
            let got: Vec<String> = systemctl_args(&call)
                .into_iter()
                .map(|a| a.into_string().unwrap())
                .collect();
            assert_eq!(got, want, "{call:?}");
        }
    }

    /// Table: `is-enabled`'s answers (systemd 259 on the dev VM printed
    /// `enabled`/rc 0, `disabled`/rc 1 and `not-found`/rc 4).
    #[test]
    fn is_enabled_answers_are_classified() {
        let enabled = parse_is_enabled("enabled\n", "", true).unwrap();
        assert!(enabled.enabled && !enabled.elevated);
        assert!(
            parse_is_enabled("enabled-runtime\n", "", true)
                .unwrap()
                .enabled
        );
        for state in ["disabled", "linked", "masked", "static", "indirect"] {
            let r = parse_is_enabled(&format!("{state}\n"), "", false).unwrap();
            assert!(!r.enabled, "{state}");
            assert!(r.note.unwrap().contains(state));
        }
        assert_eq!(parse_is_enabled("not-found\n", "", false), None);
        assert_eq!(
            parse_is_enabled(
                "",
                "Failed to get unit file state for tornect-host.service: No such file or directory",
                false
            ),
            None
        );
    }

    const SID: &str = "S-1-5-21-1004336348-1177238915-682003330-1001";

    /// A `/Query` that succeeded with `text`, classified.
    fn queried(text: &str) -> AutostartState {
        classify_task_query(
            &TaskQuery {
                text: text.to_owned(),
                success: true,
                message: String::new(),
            },
            &TaskFile::Present,
        )
        .unwrap()
    }

    #[test]
    fn the_task_xml_names_this_user_and_the_run_level() {
        let xml = task_xml(
            &spec("C:\\Program Files\\Tornect\\tornect.exe", None),
            SID,
            false,
        )
        .unwrap();
        assert!(
            xml.contains("<Command>&quot;C:\\Program Files\\Tornect\\tornect.exe&quot;</Command>"),
            "{xml}"
        );
        assert!(xml.contains("<Arguments>--background</Arguments>"));
        assert!(xml.contains("<RunLevel>LeastPrivilege</RunLevel>"));
        assert_eq!(
            xml.matches(&format!("<UserId>{SID}</UserId>")).count(),
            2,
            "trigger and principal"
        );
        for setting in [
            "<LogonType>InteractiveToken</LogonType>",
            "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>",
            "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>",
            "<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>",
            "<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>",
            "<Hidden>false</Hidden>",
        ] {
            assert!(xml.contains(setting), "missing {setting}");
        }
        let elevated = task_xml(
            &spec("C:\\Program Files\\Tornect\\tornect.exe", None),
            SID,
            true,
        )
        .unwrap();
        assert!(elevated.contains("<RunLevel>HighestAvailable</RunLevel>"));
        // What the definition says is what the status parser reads back.
        match queried(&xml) {
            AutostartState::Registered(r) => {
                assert!(r.enabled && !r.elevated);
                assert_eq!(
                    r.command.as_deref(),
                    Some("\"C:\\Program Files\\Tornect\\tornect.exe\" --background")
                );
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            queried(&elevated),
            AutostartState::Registered(Registration {
                elevated: true,
                enabled: true,
                ..
            })
        ));
        // The file schtasks reads is UTF-16LE with a BOM.
        let bytes = task_xml_file_bytes(&xml);
        assert_eq!(&bytes[..4], &[0xFF, 0xFE, b'<', 0]);
        assert_eq!(decode_console_output(&bytes), xml);
    }

    /// Slice-F F1-5: the elevated task cannot be started on demand, so a
    /// program running as the user cannot start the elevated host whenever
    /// it likes (should the task's security descriptor let the filtered token
    /// run it at all: NEEDS-DEVICE); the plain task still can.
    #[test]
    fn only_the_plain_task_starts_on_demand() {
        let exe = spec("C:\\Program Files\\Tornect\\tornect.exe", None);
        let plain = task_xml(&exe, SID, false).unwrap();
        assert!(
            plain.contains("<AllowStartOnDemand>true</AllowStartOnDemand>"),
            "{plain}"
        );
        let elevated = task_xml(&exe, SID, true).unwrap();
        assert!(
            elevated.contains("<AllowStartOnDemand>false</AllowStartOnDemand>")
                && !elevated.contains("<AllowStartOnDemand>true"),
            "the elevated task starts on demand:\n{elevated}"
        );
    }

    #[test]
    fn task_paths_are_quoted_or_refused() {
        assert_eq!(
            task_command("C:\\Users\\Ana Maria\\Tornect\\tornect.exe").unwrap(),
            "\"C:\\Users\\Ana Maria\\Tornect\\tornect.exe\""
        );
        assert!(task_command("\\\\server\\share\\tornect.exe").is_ok());
        for bad in [
            "tornect.exe",
            "Tornect\\tornect.exe",
            "\\\\?\\C:\\t\\tornect.exe",
            "C:\\100%\\tornect.exe",
            "C:\\%TEMP%\\tornect.exe",
            "C:\\a\"b\\tornect.exe",
            "C:\\a\nb\\tornect.exe",
        ] {
            assert!(task_command(bad).is_err(), "{bad:?} must be refused");
        }
        // SIDs are checked before they reach the XML.
        for bad in [
            "",
            "S-1-",
            "S-1-5-21-x",
            "S-1-5-21-1</UserId><UserId>S-1-5-18",
        ] {
            assert!(
                task_xml(&spec("C:\\t\\tornect.exe", None), bad, false).is_err(),
                "{bad:?}"
            );
        }
    }

    /// Review finding E2-2: on Windows a custom home has no private ACL, so the
    /// task never serves one.
    #[test]
    fn the_windows_task_refuses_a_custom_home() {
        match task_xml(
            &spec("C:\\t\\tornect.exe", Some("C:\\tornect-host")),
            SID,
            false,
        ) {
            Err(AutostartError::Unavailable(m)) => assert!(m.contains("E2-2"), "{m}"),
            other => panic!("{other:?}"),
        }
    }

    /// Review finding E2-2: on Windows, Tornect's own directories get no
    /// private permissions yet, so a `--home` or `TORNECT_HOME` is taken only
    /// inside the user's profile folder, whose permissions keep other accounts
    /// out; the refusal is the start-at-login task's rule and text.
    #[test]
    fn a_windows_home_is_taken_only_inside_the_profile() {
        let profile = Some("C:\\Users\\me");
        for home in [
            "C:\\Users\\me\\tornect-h1",
            "c:\\users\\ME\\AppData\\Local\\t",
            "C:\\Users\\me",
            "C:\\Users\\me\\",
        ] {
            assert_eq!(windows_home_ok(home, profile), Ok(()), "{home}");
        }
        for home in [
            "C:\\tornect-home",
            "C:\\Users\\Public\\tornect",
            "C:\\Users\\meX\\t",
            "C:\\Users\\me\\..\\other\\t",
            "D:\\shared\\t",
            "\\\\server\\share\\t",
            "\\\\?\\C:\\Users\\me\\t",
        ] {
            match windows_home_ok(home, profile) {
                Err(m) => {
                    assert!(m.contains(home), "{m}");
                    assert!(m.contains(WINDOWS_HOME_RULE), "{m}");
                }
                Ok(()) => panic!("{home} must be refused"),
            }
        }
        // A profile the OS would not name: refused, never guessed.
        assert!(windows_home_ok("C:\\Users\\me\\t", None).is_err());
        // One rule: the task's refusal says the same.
        assert!(WINDOWS_CUSTOM_HOME_REFUSAL.contains(WINDOWS_HOME_RULE));
    }

    #[test]
    fn schtasks_argument_vectors() {
        let xml = "C:\\Users\\Ana Maria\\AppData\\Local\\Temp\\tornect-autostart-1a2b.xml";
        for (call, want) in [
            (
                SchtasksCall::Create(xml),
                vec!["/Create", "/F", "/TN", "Tornect", "/XML", xml],
            ),
            (
                SchtasksCall::Delete,
                vec!["/Delete", "/TN", "Tornect", "/F"],
            ),
            (
                SchtasksCall::Query,
                vec!["/Query", "/TN", "Tornect", "/XML"],
            ),
        ] {
            assert_eq!(schtasks_args(&call), want, "{call:?}");
        }
        // As one string for ShellExecuteExW.
        assert_eq!(
            windows_command_line(&schtasks_args(&SchtasksCall::Create(xml))),
            "/Create /F /TN Tornect /XML \
             \"C:\\Users\\Ana Maria\\AppData\\Local\\Temp\\tornect-autostart-1a2b.xml\""
        );
        assert_eq!(
            windows_command_line(&["a b\\".to_owned(), "q\"x".to_owned(), String::new()]),
            "\"a b\\\\\" \"q\\\"x\" \"\""
        );
    }

    /// Canned `schtasks /Query /TN Tornect /XML` answers: present, absent,
    /// elevated, disabled — the definition as Windows exports it (UTF-16 to a
    /// pipe on some systems, ASCII on others).
    #[test]
    fn schtasks_query_answers_are_parsed() {
        let exported = |settings_enabled: &str, trigger_enabled: &str, run_level: &str| {
            format!(
                "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n\
<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n\
  <RegistrationInfo>\r\n    <Date>2026-09-23T18:00:00</Date>\r\n    <Author>PC\\ana</Author>\r\n    <URI>\\Tornect</URI>\r\n  </RegistrationInfo>\r\n\
  <Triggers>\r\n    <LogonTrigger>\r\n      <Enabled>{trigger_enabled}</Enabled>\r\n      <UserId>PC\\ana</UserId>\r\n    </LogonTrigger>\r\n  </Triggers>\r\n\
  <Principals>\r\n    <Principal id=\"Author\">\r\n      <UserId>{SID}</UserId>\r\n      <LogonType>InteractiveToken</LogonType>\r\n      <RunLevel>{run_level}</RunLevel>\r\n    </Principal>\r\n  </Principals>\r\n\
  <Settings>\r\n    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\r\n    <IdleSettings>\r\n      <StopOnIdleEnd>false</StopOnIdleEnd>\r\n    </IdleSettings>\r\n    <Enabled>{settings_enabled}</Enabled>\r\n    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\r\n  </Settings>\r\n\
  <Actions Context=\"Author\">\r\n    <Exec>\r\n      <Command>\"C:\\Program Files\\Tornect\\tornect.exe\"</Command>\r\n      <Arguments>--background</Arguments>\r\n    </Exec>\r\n  </Actions>\r\n</Task>\r\n"
            )
        };
        // Present.
        let present = exported("true", "true", "LeastPrivilege");
        assert_eq!(
            queried(&present),
            AutostartState::Registered(Registration {
                enabled: true,
                elevated: false,
                command: Some(
                    "\"C:\\Program Files\\Tornect\\tornect.exe\" --background".to_owned(),
                ),
                note: None,
                unreadable: false,
            })
        );
        // The same bytes as UTF-16LE with a BOM decode to the same answer.
        let utf16 = task_xml_file_bytes(&present);
        assert_eq!(queried(&decode_console_output(&utf16)), queried(&present));
        // Elevated.
        let elevated = exported("true", "true", "HighestAvailable");
        assert!(matches!(
            queried(&elevated),
            AutostartState::Registered(Registration {
                enabled: true,
                elevated: true,
                ..
            })
        ));
        // Disabled task, and a disabled trigger.
        for (xml, why) in [
            (
                exported("false", "true", "LeastPrivilege"),
                "the task is disabled",
            ),
            (
                exported("true", "false", "LeastPrivilege"),
                "logon trigger is disabled",
            ),
        ] {
            match queried(&xml) {
                AutostartState::Registered(r) => {
                    assert!(!r.enabled);
                    assert!(r.note.unwrap().contains(why));
                }
                other => panic!("{other:?}"),
            }
        }
        // Absent: schtasks fails ("ERROR: The system cannot find the file
        // specified." in English; localized elsewhere, so the status and the
        // task's file decide, slice-F F1-1).
        let failed = TaskQuery {
            text: String::new(),
            success: false,
            message: "ERROR: The system cannot find the file specified.".to_owned(),
        };
        assert_eq!(
            classify_task_query(&failed, &TaskFile::Missing).unwrap(),
            AutostartState::Absent
        );
        assert_eq!(parse_task_definition(""), None);
    }

    /// Slice-F F1-1: a failed `/Query` is `Absent` only when the task's file
    /// is definitely not there. Before, every failure read as "not registered"
    /// ("ERROR: Access is denied." included), so `uninstall` could report a
    /// removal and leave an elevated task in place.
    #[test]
    fn a_failed_query_is_absent_only_beside_a_definite_not_found() {
        let failed = TaskQuery {
            text: String::new(),
            success: false,
            message: "ERROR: Access is denied.".to_owned(),
        };
        let ok = TaskQuery {
            text: task_xml(&spec("C:\\t\\tornect.exe", None), SID, false).unwrap(),
            success: true,
            message: String::new(),
        };
        let garbled = TaskQuery {
            text: "INFO: something else".to_owned(),
            success: true,
            message: String::new(),
        };
        let files = [
            TaskFile::Missing,
            TaskFile::Present,
            TaskFile::Unknown("The network path was not found.".to_owned()),
        ];
        match classify_task_query(&failed, &TaskFile::Present) {
            Ok(AutostartState::Registered(r)) => {
                assert!(r.unreadable, "{r:?}");
                assert!(
                    r.note.as_deref().unwrap_or("").contains("cannot read"),
                    "{r:?}"
                );
            }
            other => panic!("a task that exists but cannot be read: {other:?}"),
        }
        for file in &files {
            // A readable definition is what it says, whatever the file test.
            assert!(
                matches!(
                    classify_task_query(&ok, file),
                    Ok(AutostartState::Registered(Registration {
                        unreadable: false,
                        ..
                    }))
                ),
                "{file:?}"
            );
            // A success without a definition is not an answer.
            assert!(
                classify_task_query(&garbled, file).is_err(),
                "garbled output with {file:?}"
            );
        }
        assert_eq!(
            classify_task_query(&failed, &TaskFile::Missing).unwrap(),
            AutostartState::Absent
        );
        match classify_task_query(&failed, &files[2]) {
            Err(AutostartError::Failed(m)) => {
                assert!(m.contains("could not read the start-at-login task"), "{m}");
            }
            other => panic!("nothing known must be an error: {other:?}"),
        }
        // The file test itself: `PermissionDenied` still proves the file.
        let kind = |k| TaskFile::from_lookup(Err(std::io::Error::from(k)));
        assert_eq!(TaskFile::from_lookup(Ok(())), TaskFile::Present);
        assert_eq!(kind(std::io::ErrorKind::NotFound), TaskFile::Missing);
        assert_eq!(
            kind(std::io::ErrorKind::PermissionDenied),
            TaskFile::Present
        );
        assert!(matches!(
            kind(std::io::ErrorKind::InvalidInput),
            TaskFile::Unknown(_)
        ));
        // An unreadable task raises the elevated warning.
        let Probe::Warn(m) = readiness_probe(&classify_task_query(&failed, &TaskFile::Present))
        else {
            panic!("an unreadable task must warn")
        };
        assert!(
            m.contains("ELEVATED") && m.contains("administrator session"),
            "{m}"
        );
    }

    /// A Task Scheduler as the backend sees it: one task, which exists or
    /// not, is readable by this account or not, and is elevated or not.
    #[derive(Default)]
    struct FakeTasks {
        task: std::sync::Mutex<Option<FakeTask>>,
        /// What the next `/Create` registers.
        creates: Option<FakeTask>,
        /// `/Delete` answers success but leaves the task.
        delete_is_a_no_op: bool,
        /// This account is a standard one (default: an administrator).
        standard_account: bool,
        /// Every change: (the call, through UAC).
        calls: std::sync::Mutex<Vec<(String, bool)>>,
    }

    #[derive(Clone, Copy, Debug)]
    struct FakeTask {
        readable: bool,
        elevated: bool,
        /// What differs from the definition `task_install` wrote.
        swap: Option<Swap>,
    }

    /// One field of a registered task that is not what was written.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Swap {
        Command,
        Principal,
        RunLevel,
    }

    /// The executable the fake's tasks run.
    const FAKE_EXE: &str = "C:\\t\\tornect.exe";

    impl FakeTasks {
        fn with(task: FakeTask) -> Self {
            Self {
                task: std::sync::Mutex::new(Some(task)),
                ..Self::default()
            }
        }

        fn calls(&self) -> Vec<(String, bool)> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl TaskScheduling for FakeTasks {
        fn query(&self) -> Result<TaskQuery, AutostartError> {
            Ok(match *self.task.lock().unwrap() {
                Some(t) if t.readable => TaskQuery {
                    text: task_xml(
                        &spec(
                            if t.swap == Some(Swap::Command) {
                                "C:\\Users\\Public\\evil.exe"
                            } else {
                                FAKE_EXE
                            },
                            None,
                        ),
                        if t.swap == Some(Swap::Principal) {
                            "S-1-5-18"
                        } else {
                            SID
                        },
                        t.elevated,
                    )
                    .unwrap(),
                    success: true,
                    message: String::new(),
                },
                Some(_) => TaskQuery {
                    text: String::new(),
                    success: false,
                    message: "ERROR: Access is denied.".to_owned(),
                },
                None => TaskQuery {
                    text: String::new(),
                    success: false,
                    message: "ERROR: The system cannot find the file specified.".to_owned(),
                },
            })
        }

        fn task_file(&self) -> TaskFile {
            match *self.task.lock().unwrap() {
                Some(_) => TaskFile::Present,
                None => TaskFile::Missing,
            }
        }

        fn administrator(&self) -> std::io::Result<bool> {
            Ok(!self.standard_account)
        }

        fn is_this_account(&self, principal: &str) -> bool {
            principal.eq_ignore_ascii_case(SID)
        }

        fn change(&self, call: &SchtasksCall<'_>, elevated: bool) -> Result<(), AutostartError> {
            self.calls
                .lock()
                .unwrap()
                .push((format!("{call:?}"), elevated));
            let mut task = self.task.lock().unwrap();
            match call {
                SchtasksCall::Create(_) => *task = self.creates,
                SchtasksCall::Delete => match *task {
                    // What a standard token gets for an administrator's task.
                    Some(t) if (t.elevated || !t.readable) && !elevated => {
                        return Err(AutostartError::Failed(
                            "schtasks.exe failed: ERROR: Access is denied.".to_owned(),
                        ));
                    }
                    Some(_) if self.delete_is_a_no_op => {}
                    _ => *task = None,
                },
                SchtasksCall::Query => {}
            }
            Ok(())
        }
    }

    /// Migration (r7; DA-3, DA-13): an earlier version's elevated task, or
    /// an unreadable one, is removed through the UAC prompt before the plain
    /// task; a plain task stays; a refused or ineffective delete fails, so
    /// the two are never registered together.
    #[test]
    fn an_earlier_elevated_task_is_removed_through_the_uac_prompt() {
        for (task, removed) in [
            (
                FakeTask {
                    readable: true,
                    elevated: true,
                    swap: None,
                },
                true,
            ),
            (
                FakeTask {
                    readable: false,
                    elevated: false,
                    swap: None,
                },
                true,
            ),
            (
                FakeTask {
                    readable: true,
                    elevated: false,
                    swap: None,
                },
                false,
            ),
        ] {
            let ts = FakeTasks::with(task);
            assert_eq!(migrate_elevated_task(&ts).unwrap(), removed, "{task:?}");
            if removed {
                assert_eq!(ts.calls(), vec![("Delete".to_owned(), true)], "{task:?}");
                assert!(ts.task.lock().unwrap().is_none());
            } else {
                assert!(ts.calls().is_empty(), "{task:?}");
            }
        }
        assert!(
            !migrate_elevated_task(&FakeTasks::default()).unwrap(),
            "none"
        );
        let stuck = FakeTasks {
            delete_is_a_no_op: true,
            ..FakeTasks::with(FakeTask {
                readable: true,
                elevated: true,
                swap: None,
            })
        };
        assert!(migrate_elevated_task(&stuck).is_err(), "still there");
        assert!(ELEVATED_TASK_GONE.contains("per session"));
    }

    /// The definition `task_install` wrote for the fake's executable.
    fn written(elevated: bool) -> String {
        task_xml(&spec(FAKE_EXE, None), SID, elevated).unwrap()
    }

    /// Slice-F F1-2: what was registered is read back and compared with what
    /// was written (the principal, the run level, the command); a task that
    /// differs is removed, through the UAC prompt when it or the install was
    /// elevated, and the install fails.
    #[test]
    fn a_task_registered_other_than_written_is_removed() {
        for swap in [Swap::Command, Swap::Principal, Swap::RunLevel] {
            for elevated in [false, true] {
                // What the Task Scheduler holds after the `/Create`.
                let registered_elevated = if swap == Swap::RunLevel {
                    !elevated
                } else {
                    elevated
                };
                let tasks = FakeTasks {
                    creates: Some(FakeTask {
                        readable: true,
                        elevated: registered_elevated,
                        swap: Some(swap),
                    }),
                    ..FakeTasks::default()
                };
                match task_install(&tasks, "C:\\x\\task.xml", &written(elevated), elevated) {
                    Err(AutostartError::Failed(m)) => {
                        assert!(m.contains("not the one Tornect wrote"), "{swap:?}: {m}");
                    }
                    other => panic!("{swap:?} (elevated: {elevated}) was kept: {other:?}"),
                }
                assert_eq!(
                    tasks.calls().last(),
                    Some(&("Delete".to_owned(), elevated || registered_elevated)),
                    "{swap:?} (elevated: {elevated})"
                );
                assert!(
                    tasks.task.lock().unwrap().is_none(),
                    "{swap:?} (elevated: {elevated}): still registered"
                );
            }
        }
    }

    /// Review P2-I2: a comment or CDATA section that holds `>` ends early for
    /// the element count and opens a phantom element, which hides a second
    /// action; a definition that holds one, a DOCTYPE, or a processing
    /// instruction after its one XML declaration is not the one written. The
    /// declaration the fixture (and `schtasks /Query /XML`) starts with is
    /// accepted.
    #[test]
    fn markup_that_could_hide_an_action_is_not_the_one_written() {
        let plain = written(false);
        assert!(
            plain.starts_with("<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n<Task "),
            "{plain}"
        );
        let me = |p: &str| p.eq_ignore_ascii_case(SID);
        assert_eq!(
            registered_matches(&task_facts(&plain), &task_facts(&plain), &me),
            Ok(())
        );
        let second = "<Exec><Command>C:\\Users\\Public\\evil.exe</Command></Exec>";
        for hide in [
            "<WorkingDirectory><![CDATA[ > <x> ]]></WorkingDirectory>",
            "<!-- > <x> -->",
            "<?tornect > <x> ?>",
        ] {
            let two = plain
                .replace("</Arguments>", &format!("</Arguments>{hide}"))
                .replace("</Exec>", &format!("</Exec>{second}"));
            assert!(
                registered_matches(&task_facts(&plain), &task_facts(&two), &me).is_err(),
                "{hide} hid a second action"
            );
        }
        for extra in ["<!DOCTYPE Task>", "<?xml-stylesheet href=\"x\"?>"] {
            let marked = plain.replace("\r\n<Task ", &format!("\r\n{extra}<Task "));
            assert_ne!(marked, plain);
            assert!(
                registered_matches(&task_facts(&plain), &task_facts(&marked), &me).is_err(),
                "{extra} was taken"
            );
        }
    }

    /// Review N-3: a registered definition that holds a second action after
    /// Tornect's (another `<Exec>`, or a `<ComHandler>`) would run it too at
    /// every logon; it is not the one written.
    #[test]
    fn a_task_with_a_second_action_is_not_the_one_written() {
        let plain = written(false);
        let me = |p: &str| p.eq_ignore_ascii_case(SID);
        for extra in [
            "<Exec><Command>C:\\Users\\Public\\evil.exe</Command></Exec>",
            "<ComHandler><ClassId>{00000000-0000-0000-0000-000000000000}</ClassId></ComHandler>",
        ] {
            let two = plain.replace("</Exec>", &format!("</Exec>{extra}"));
            assert_ne!(two, plain);
            assert!(
                registered_matches(&task_facts(&plain), &task_facts(&two), &me).is_err(),
                "a task that also runs {extra} matched"
            );
        }
        assert_eq!(
            registered_matches(&task_facts(&plain), &task_facts(&plain), &me),
            Ok(())
        );
    }

    /// Slice-F F1-2, the compare itself: a swapped command or arguments, a
    /// swapped principal, or `LeastPrivilege` against `HighestAvailable` is a
    /// mismatch; the principal may come back as a name that is this account.
    #[test]
    fn registered_matches_finds_every_swap() {
        let plain = task_facts(&written(false));
        assert_eq!(plain.principal.as_deref(), Some(SID));
        assert_eq!(plain.run_level.as_deref(), Some("LeastPrivilege"));
        assert_eq!(plain.command.as_deref(), Some("\"C:\\t\\tornect.exe\""));
        assert_eq!(plain.arguments.as_deref(), Some("--background"));
        let me = |p: &str| p.eq_ignore_ascii_case(SID) || p.eq_ignore_ascii_case("PC\\me");
        assert_eq!(registered_matches(&plain, &plain, &me), Ok(()));
        let as_name = TaskFacts {
            principal: Some("pc\\ME".to_owned()),
            command: Some("\"c:\\T\\TORNECT.exe\"".to_owned()),
            ..plain.clone()
        };
        assert_eq!(registered_matches(&plain, &as_name, &me), Ok(()));
        // A run level the scheduler leaves out is its default.
        let default_level = TaskFacts {
            run_level: None,
            ..plain.clone()
        };
        assert_eq!(registered_matches(&plain, &default_level, &me), Ok(()));
        for (what, swapped) in [
            (
                "command",
                TaskFacts {
                    command: Some("\"C:\\Users\\Public\\evil.exe\"".to_owned()),
                    ..plain.clone()
                },
            ),
            (
                "arguments",
                TaskFacts {
                    arguments: Some("host --capture test-card".to_owned()),
                    ..plain.clone()
                },
            ),
            (
                "principal",
                TaskFacts {
                    principal: Some("S-1-5-18".to_owned()),
                    ..plain.clone()
                },
            ),
            (
                "no principal",
                TaskFacts {
                    principal: None,
                    ..plain.clone()
                },
            ),
            (
                "run level",
                TaskFacts {
                    run_level: Some("HighestAvailable".to_owned()),
                    ..plain.clone()
                },
            ),
        ] {
            assert!(
                registered_matches(&plain, &swapped, &me).is_err(),
                "{what} swapped, and it matched"
            );
        }
        let elevated = task_facts(&written(true));
        assert!(registered_matches(&elevated, &plain, &me).is_err());
    }

    /// §B.1.1 (decision M1-58): the at-logon task runs the app in the
    /// background, `tornect.exe --background`, and the read-back compare checks
    /// that argument: a task that runs the headless host (an earlier
    /// version's) is not the one written. The systemd unit keeps `host`.
    #[test]
    fn the_task_runs_the_app_in_the_background() {
        let launch = spec("C:\\Program Files\\Tornect\\tornect.exe", None);
        assert_eq!(launch.app_args(), vec![OsString::from("--background")]);
        assert_eq!(launch.args(), vec![OsString::from("host")], "the unit's");
        assert_eq!(
            spec("/usr/bin/tornect", Some("/srv/t")).app_args(),
            ["--home", "/srv/t", "--background"]
                .map(OsString::from)
                .to_vec()
        );
        let xml = task_xml(&launch, SID, false).unwrap();
        assert!(xml.contains("<Arguments>--background</Arguments>"), "{xml}");
        assert!(!xml.contains(">host<"), "{xml}");
        let written = task_facts(&xml);
        let me = |p: &str| p.eq_ignore_ascii_case(SID);
        assert_eq!(registered_matches(&written, &written, &me), Ok(()));
        let the_host = TaskFacts {
            arguments: Some("host".to_owned()),
            ..written.clone()
        };
        assert!(
            registered_matches(&written, &the_host, &me).is_err(),
            "a task that runs the headless host is not the one written"
        );
    }

    /// Slice-F F1-1: an elevated or unreadable task is removed through the
    /// UAC prompt, never by the plain delete, and "removed" means the definite
    /// not-found test says so.
    #[test]
    fn an_elevated_or_unreadable_task_is_removed_through_the_uac_prompt() {
        for task in [
            FakeTask {
                readable: true,
                elevated: true,
                swap: None,
            },
            FakeTask {
                readable: false,
                elevated: false,
                swap: None,
            },
        ] {
            let tasks = FakeTasks::with(task);
            assert_eq!(
                task_uninstall(&tasks).unwrap(),
                AutostartState::Absent,
                "{task:?}"
            );
            assert_eq!(tasks.calls(), vec![("Delete".to_owned(), true)], "{task:?}");
        }
        // This user's own task: the plain delete.
        let tasks = FakeTasks::with(FakeTask {
            readable: true,
            elevated: false,
            swap: None,
        });
        assert_eq!(task_uninstall(&tasks).unwrap(), AutostartState::Absent);
        assert_eq!(tasks.calls(), vec![("Delete".to_owned(), false)]);
        // Nothing there: nothing to do.
        let tasks = FakeTasks::default();
        assert_eq!(task_uninstall(&tasks).unwrap(), AutostartState::Absent);
        assert!(tasks.calls().is_empty());
    }

    /// Slice-F F1-1: a delete that leaves the task is a failure that names
    /// the manual step, never a removal.
    #[test]
    fn a_delete_that_leaves_the_task_is_a_failure() {
        for task in [
            FakeTask {
                readable: true,
                elevated: false,
                swap: None,
            },
            FakeTask {
                readable: false,
                elevated: false,
                swap: None,
            },
        ] {
            let tasks = FakeTasks {
                delete_is_a_no_op: true,
                ..FakeTasks::with(task)
            };
            match task_uninstall(&tasks) {
                Err(AutostartError::Failed(m)) => {
                    assert!(m.contains("schtasks /Delete /TN Tornect /F"), "{m}");
                }
                other => panic!("{task:?}: {other:?}"),
            }
        }
    }

    /// Slice-F F1-1: a task this account registered but cannot read back is
    /// reported as registered, never as "nothing starts at login".
    #[test]
    fn an_install_that_cannot_read_the_task_back_says_so() {
        let tasks = FakeTasks {
            creates: Some(FakeTask {
                readable: false,
                elevated: true,
                swap: None,
            }),
            ..FakeTasks::default()
        };
        match task_install(&tasks, "C:\\x\\task.xml", &written(true), true) {
            Ok(AutostartState::Registered(r)) => {
                assert!(r.unreadable && r.elevated, "{r:?}");
                assert!(
                    r.note
                        .as_deref()
                        .unwrap_or("")
                        .contains("cannot read it back"),
                    "{r:?}"
                );
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            tasks.calls(),
            vec![("Create(\"C:\\\\x\\\\task.xml\")".to_owned(), true)]
        );
    }

    /// Slice-F review §3.2, decided 2026-09-24: a standard account never gets
    /// the elevated task. Approved with an administrator's password over its
    /// shoulder, the task would be the administrator's, and the standard
    /// account could neither read nor remove it. The refusal comes before any
    /// UAC prompt.
    #[test]
    fn a_standard_account_never_gets_the_elevated_task() {
        let tasks = FakeTasks {
            standard_account: true,
            creates: Some(FakeTask {
                readable: false,
                elevated: true,
                swap: None,
            }),
            ..FakeTasks::default()
        };
        match task_install(&tasks, "C:\\x\\task.xml", &written(true), true) {
            Err(AutostartError::Unavailable(m)) => {
                assert!(m.contains("needs an administrator account"), "{m}");
            }
            other => panic!("a standard account's elevated task went on: {other:?}"),
        }
        assert!(
            tasks.calls().is_empty(),
            "no UAC prompt for a standard account: {:?}",
            tasks.calls()
        );
    }

    /// The account check itself: an administrator (its filtered token
    /// included, which the Windows check counts) passes; a standard account
    /// and a check that fails are refused; the non-elevated task needs none.
    #[test]
    fn only_an_administrator_account_passes_the_elevated_check() {
        let admin = FakeTasks::default();
        assert!(elevated_task_account_ok(&admin).is_ok());
        let standard = FakeTasks {
            standard_account: true,
            ..FakeTasks::default()
        };
        match elevated_task_account_ok(&standard) {
            Err(AutostartError::Unavailable(m)) => {
                assert_eq!(m, ELEVATED_NEEDS_ADMINISTRATOR);
                assert!(m.contains("for the normal task"), "{m}");
            }
            other => panic!("{other:?}"),
        }
        struct Broken;
        impl TaskScheduling for Broken {
            fn query(&self) -> Result<TaskQuery, AutostartError> {
                unreachable!()
            }
            fn task_file(&self) -> TaskFile {
                unreachable!()
            }
            fn change(&self, _: &SchtasksCall<'_>, _: bool) -> Result<(), AutostartError> {
                unreachable!()
            }
            fn administrator(&self) -> std::io::Result<bool> {
                Err(std::io::Error::other("access denied"))
            }
            fn is_this_account(&self, _: &str) -> bool {
                unreachable!()
            }
        }
        assert!(matches!(
            elevated_task_account_ok(&Broken),
            Err(AutostartError::Unavailable(m)) if m.contains("access denied")
        ));
        // The plain task: a standard account registers its own, no check.
        let standard = FakeTasks {
            standard_account: true,
            creates: Some(FakeTask {
                readable: true,
                elevated: false,
                swap: None,
            }),
            ..FakeTasks::default()
        };
        assert!(matches!(
            task_install(&standard, "C:\\x\\task.xml", &written(false), false),
            Ok(AutostartState::Registered(_))
        ));
        assert_eq!(
            standard.calls(),
            vec![("Create(\"C:\\\\x\\\\task.xml\")".to_owned(), false)]
        );
    }

    /// A file system for the location check: path → (owner, group, mode,
    /// symlink).
    fn facts(
        table: &[(&str, u32, u32, u32, bool)],
    ) -> impl Fn(&Path) -> std::io::Result<PathFacts> + use<> {
        let map: std::collections::HashMap<PathBuf, PathFacts> = table
            .iter()
            .map(|&(p, uid, gid, mode, symlink)| {
                (
                    PathBuf::from(p),
                    PathFacts {
                        uid,
                        gid,
                        mode,
                        symlink,
                    },
                )
            })
            .collect();
        move |p: &Path| {
            map.get(p)
                .copied()
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
        }
    }

    /// Slice-F F2-2 (the Linux side of default 1, and F2-6's characters): the
    /// unit runs only an executable that nobody but this user or root can
    /// replace, on a path systemd takes as written. Before, `preflight`
    /// accepted every one of these.
    #[test]
    fn only_an_executable_nobody_else_can_replace_starts_at_login() {
        const U: u32 = 1000;
        const G: u32 = 1000;
        let fs = facts(&[
            ("/", 0, 0, 0o40755, false),
            ("/home", 0, 0, 0o40755, false),
            ("/home/u", U, G, 0o40750, false),
            ("/home/u/.local", U, G, 0o40755, false),
            ("/home/u/.local/bin", U, G, 0o40755, false),
            ("/home/u/.local/bin/tornect", U, G, 0o100755, false),
            // A user-private group under umask 002.
            ("/home/u/apps", U, G, 0o40775, false),
            ("/home/u/apps/tornect", U, G, 0o100775, false),
            ("/home/u/theirs", U, G, 0o40755, false),
            ("/home/u/theirs/tornect", 1001, 1001, 0o100755, false),
            ("/home/u/link", U, G, 0o120777, true),
            ("/home/u/link/tornect", U, G, 0o100755, false),
            ("/tmp", 0, 0, 0o41777, false),
            ("/tmp/t", U, G, 0o40755, false),
            ("/tmp/t/tornect", U, G, 0o100755, false),
            ("/opt", 0, 0, 0o40755, false),
            ("/opt/shared", 0, 50, 0o42775, false),
            ("/opt/shared/tornect", U, G, 0o100755, false),
            ("/usr", 0, 0, 0o40755, false),
            ("/usr/bin", 0, 0, 0o40755, false),
            ("/usr/bin/tornect", 0, 0, 0o100755, false),
            ("/home/u/a$b", U, G, 0o40755, false),
            ("/home/u/a$b/tornect", U, G, 0o100755, false),
            ("/home/u/a\"b", U, G, 0o40755, false),
            ("/home/u/a\"b/tornect", U, G, 0o100755, false),
            ("/home/u/a'b", U, G, 0o40755, false),
            ("/home/u/a'b/tornect", U, G, 0o100755, false),
            ("/home/u/a\\b", U, G, 0o40755, false),
            ("/home/u/a\\b/tornect", U, G, 0o100755, false),
        ]);
        let check = |p: &str| unix_exe_location_ok(Path::new(p), U, G, &fs);
        for ok in [
            "/home/u/.local/bin/tornect",
            "/home/u/apps/tornect",
            "/usr/bin/tornect",
        ] {
            assert!(check(ok).is_ok(), "{ok}: {:?}", check(ok));
        }
        for (bad, why) in [
            ("/tmp/t/tornect", "every account"),
            ("/opt/shared/tornect", "group"),
            ("/home/u/theirs/tornect", "another account"),
            ("/home/u/link/tornect", "symbolic link"),
            ("/home/u/a$b/tornect", "$"),
            ("/home/u/a\"b/tornect", "\""),
            ("/home/u/a'b/tornect", "'"),
            ("/home/u/a\\b/tornect", "\\"),
            ("/nowhere/tornect", "could not check"),
        ] {
            match check(bad) {
                Err(AutostartError::Unavailable(m)) => assert!(m.contains(why), "{bad}: {m}"),
                other => panic!("{bad} must be refused: {other:?}"),
            }
        }
    }

    /// The ids the Linux check compares with are the real ones.
    #[test]
    fn the_real_ids_are_read_from_the_status_file() {
        let status = "Name:\ttornect\nUid:\t1000\t1001\t1000\t1000\nGid:\t100\t0\t100\t100\n";
        assert_eq!(parse_status_ids(status), Some((1000, 100)));
        assert_eq!(parse_status_ids("Name:\tx\n"), None);
    }

    /// Default 1 (slice F): the non-elevated task runs a `tornect.exe` under
    /// the user's profile or Program Files only; the elevated one under
    /// Program Files only (F1-4: both folders come from the OS, not the
    /// environment, in the backend).
    #[test]
    fn the_windows_task_runs_only_from_the_profile_or_program_files() {
        let (profile, pf) = (Some("C:\\Users\\me"), Some("C:\\Program Files"));
        let check = |exe: &str, elevated| windows_exe_location_ok(exe, elevated, profile, pf);
        assert!(check("C:\\Users\\me\\Apps\\tornect.exe", false).is_ok());
        assert!(check("c:\\users\\ME\\apps\\TORNECT.exe", false).is_ok());
        assert!(check("C:\\Program Files\\Tornect\\tornect.exe", false).is_ok());
        assert!(check("C:\\Program Files\\Tornect\\tornect.exe", true).is_ok());
        for (exe, elevated) in [
            ("C:\\Tools\\tornect.exe", false),
            ("C:\\Users\\meX\\tornect.exe", false),
            ("C:\\Users\\me\\..\\other\\tornect.exe", false),
            ("D:\\tornect.exe", false),
            ("C:\\Users\\me\\Apps\\tornect.exe", true),
        ] {
            assert!(
                matches!(check(exe, elevated), Err(AutostartError::Unavailable(_))),
                "{exe} (elevated: {elevated}) must be refused"
            );
        }
        // Folders the OS would not name: refused, never guessed.
        assert!(windows_exe_location_ok("C:\\Users\\me\\t.exe", false, None, None).is_err());
    }

    #[test]
    fn the_elevated_task_runs_only_from_program_files() {
        let pf = vec!["C:\\Program Files".to_owned(), String::new()];
        assert!(location_under(
            "C:\\Program Files\\Tornect\\tornect.exe",
            &pf
        ));
        assert!(location_under(
            "c:\\program files\\tornect\\TORNECT.EXE",
            &pf
        ));
        for bad in [
            "C:\\Program Files (x86)\\Tornect\\tornect.exe",
            "C:\\Program FilesX\\tornect.exe",
            "C:\\tornect\\tornect.exe",
            "C:\\Users\\ana\\Downloads\\tornect.exe",
            "C:\\Program Files\\..\\tornect\\tornect.exe",
        ] {
            assert!(!location_under(bad, &pf), "{bad}");
        }
        assert!(!location_under("C:\\Program Files\\t.exe", &[]));
    }

    /// The readiness row for every answer (§B.8.7.1 ⑥): `Ok` only for an
    /// enabled, non-elevated registration; never a gating row.
    #[test]
    fn the_readiness_row_follows_the_registration() {
        let reg = |enabled, elevated| {
            Ok(AutostartState::Registered(Registration {
                enabled,
                elevated,
                command: None,
                note: (!enabled).then(|| "systemd reports it `disabled`".to_owned()),
                unreadable: false,
            }))
        };
        assert_eq!(readiness_probe(&reg(true, false)), Probe::Ok);
        let Probe::Warn(m) = readiness_probe(&reg(true, true)) else {
            panic!("elevated must warn")
        };
        assert!(m.contains("administrator session"), "{m}");
        let Probe::Warn(m) = readiness_probe(&reg(false, false)) else {
            panic!("disabled must warn")
        };
        assert!(m.contains("disabled"), "{m}");
        let Probe::Warn(m) = readiness_probe(&Ok(AutostartState::Absent)) else {
            panic!("absent must warn")
        };
        assert!(m.contains("tornect service install"), "{m}");
        assert!(matches!(
            readiness_probe(&Ok(AutostartState::Unavailable("x".into()))),
            Probe::Warn(_)
        ));
        assert!(matches!(
            readiness_probe(&Err(AutostartError::Failed("x".into()))),
            Probe::Warn(_)
        ));
        let mut snap = tornect_core::unattended::readiness::ReadinessSnapshot::unknown();
        snap.autostart = readiness_probe(&Ok(AutostartState::Absent));
        assert_eq!(snap.host_not_ready_cause(), None, "autostart never gates");
    }

    #[test]
    fn no_autostart_refuses_and_says_why() {
        let none = NoAutostart("no backend".to_owned());
        assert!(matches!(
            none.install(false),
            Err(AutostartError::Unavailable(_))
        ));
        assert!(matches!(
            none.uninstall(),
            Err(AutostartError::Unavailable(_))
        ));
        assert!(matches!(
            none.preflight(false),
            Err(AutostartError::Unavailable(_))
        ));
        assert_eq!(
            none.status().unwrap(),
            AutostartState::Unavailable("no backend".to_owned())
        );
    }

    /// The Linux backend refuses an elevated variant before anything is written.
    #[test]
    fn a_systemd_unit_has_no_elevated_variant() {
        let tmp = tempfile::tempdir().unwrap();
        let unit = SystemdUserUnit::for_config_home(
            tmp.path(),
            "tornect-host-test.service",
            spec("/usr/bin/true", None),
        );
        assert!(matches!(
            unit.preflight(true),
            Err(AutostartError::Unavailable(_))
        ));
        assert!(matches!(
            unit.install(true),
            Err(AutostartError::Unavailable(_))
        ));
        assert!(!unit.unit_path().exists());
    }

    /// Live: `install` → `status` → `uninstall` against this user's systemd
    /// manager, with the unit file in a temporary configuration directory (the
    /// `XDG_CONFIG_HOME` the backend would read) and a unique unit name, so the
    /// real `tornect-host.service` is never touched. `enable` links the file
    /// into `~/.config/systemd/user` and `disable` removes both links; nothing
    /// is started, and nothing stays enabled. The "executable" is the real
    /// path of `/usr/bin/true`.
    ///
    /// ```text
    /// cargo test --workspace -- --ignored --nocapture live_systemd_round_trip
    /// ```
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "changes this user's systemd manager (and reverts it); run by hand"]
    #[allow(clippy::print_stderr)]
    fn live_systemd_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let mut nonce = [0u8; 4];
        getrandom::fill(&mut nonce).unwrap();
        let name = format!(
            "tornect-host-selftest-{}.service",
            data_encoding::HEXLOWER.encode(&nonce)
        );
        // The real path: the unit runs no path through a symbolic link, and
        // `/usr/bin/true` is one on some distributions.
        let exe = std::fs::canonicalize("/usr/bin/true").unwrap();
        let exe = exe.to_str().unwrap();
        let unit = SystemdUserUnit::for_config_home(
            tmp.path(),
            &name,
            spec(exe, Some("/srv/tornect test home")),
        );
        let before = unit.status().unwrap();
        eprintln!("before:    {before:?}");
        if let AutostartState::Unavailable(why) = &before {
            eprintln!("SKIPPED: {why}");
            return;
        }
        assert_eq!(before, AutostartState::Absent);

        let installed = unit.install(false);
        eprintln!("install:   {installed:?}");
        let status = unit.status();
        eprintln!("status:    {status:?}");
        let wants = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap()
            .join(".config/systemd/user/graphical-session.target.wants")
            .join(&name);
        let linked = wants.symlink_metadata().is_ok();
        eprintln!("wants link {} present: {linked}", wants.display());
        let removed = unit.uninstall();
        eprintln!("uninstall: {removed:?}");
        let after = unit.status();
        eprintln!("after:     {after:?}");

        let AutostartState::Registered(reg) = installed.unwrap() else {
            panic!("install did not register")
        };
        assert!(reg.enabled && !reg.elevated);
        assert_eq!(
            reg.command,
            Some(format!(
                "\"{exe}\" \"--home\" \"/srv/tornect test home\" \"host\""
            ))
        );
        assert!(linked, "enable must add the WantedBy link");
        assert_eq!(removed.unwrap(), AutostartState::Absent);
        assert_eq!(after.unwrap(), AutostartState::Absent);
        assert!(!unit.unit_path().exists(), "the unit file is gone");
        assert!(wants.symlink_metadata().is_err(), "nothing stays enabled");
    }
}
