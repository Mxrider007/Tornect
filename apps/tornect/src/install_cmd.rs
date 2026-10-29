//! `tornect install` and `tornect uninstall` (`docs/PLAN.md` §B.1.1, r7).
//!
//! Each is one access-increasing guard operation (§B.8.6.2: OS
//! re-authentication in a fresh dialog, no remote session for 60 s, its line
//! in `sessions.log` before the first file is written), run offline: beside a
//! running Tornect host both are refused, since no IPC operation installs.
//! Neither moves nor removes state: pairings, grants and settings stay where
//! they are (one home per user).
//!
//! - Linux: this program, read from the handle opened before anything else,
//!   is copied into `~/.local/bin` with a menu entry, a link entry for
//!   `tornect:` links and its line in `mimeapps.list`
//!   (`tornect_platform::install::LinuxInstall`); the install's line says
//!   what links do (design `invite` §4.6). The running copy's own pinned
//!   lyrebird, read before the guard's dialog
//!   (`tornect_signal::tor::bundled_lyrebird`), goes to
//!   `~/.local/bin/pt/lyrebird`; without one, a line says that the installed
//!   copy cannot use obfs4 or Snowflake bridges (the final audit before the
//!   release). Then the setting's copy
//!   about Tor at every sign-in, and the question `Start Tornect when I sign
//!   in? [y/N]`: only a yes registers the start at sign-in, for the installed
//!   copy, through `tornect service install`'s own guard operation.
//! - Windows: the Program Files steps of `tornect_platform::install`: the
//!   install's two prompts (the copy, then the installed copy writing its
//!   own entry) with this user's registration of `tornect:` links between
//!   them (never over another program's; the install's line says what links
//!   do, design `invite` §4.6), and an uninstall that, run from the
//!   installed copy, has that copy mark itself and its folder for removal at
//!   the next restart. The Program Files copy carries no lyrebird yet
//!   (decision M1-88), and the install says so.
//!
//! `tornect uninstall` removes the start at sign-in, whatever copy it runs,
//! then the link entry's line in `mimeapps.list`, the menu entry, the link
//! entry and the copy; on Windows it is refused while an
//! administrator grant exists or the administrator helper task is registered,
//! and while Tornect cannot read its grants.

use std::path::PathBuf;
use std::sync::Arc;

use tornect_core::Paths;
use tornect_core::session_log::{Actor, SessionEvent, SessionRecord};
use tornect_core::unattended::guard::{ExternalOp, GuardError};
use tornect_core::unattended::ipc::{IpcOp, IpcRequest, IpcResponse, codes};
use tornect_platform::autostart::{Autostart, AutostartState, LaunchSpec};
use tornect_platform::install::InstallError;

use crate::unattended::{self, Console, HostContext};

/// The question after an install (§B.1.1: "Start Tornect when I sign in", a
/// yes/no question whose default is no).
pub(crate) const SIGN_IN_QUESTION: &str = "Start Tornect when I sign in? [y/N]";

/// Why `install` and `uninstall` refuse beside a running Tornect host.
pub(crate) const CLOSE_FIRST: &str = "Close Tornect before installing or removing it.";

/// What a Linux install says once its files are written, by what it did
/// about `tornect:` links in `mimeapps` (design `invite` §4.6). The install
/// never fails over the links: the program works, and pasting an invitation
/// always does.
#[cfg(target_os = "linux")]
pub(crate) fn linux_installed(
    links: &tornect_platform::install::LinkHandler,
    mimeapps: &std::path::Path,
) -> String {
    use tornect_platform::install::{LINK_ENTRY, LINK_MIME, LinkHandler};
    const INSTALLED: &str = "Tornect is installed in ~/.local/bin, with a menu entry";
    let path = mimeapps.display();
    match links {
        LinkHandler::Registered => format!("{INSTALLED}; tornect:// links open it."),
        LinkHandler::OtherDefault => format!(
            "{INSTALLED}. tornect:// links open another program here ({path} says so); Tornect \
             left that as it is."
        ),
        LinkHandler::TurnedOff => format!(
            "{INSTALLED}. tornect:// links are turned off for Tornect in {path}; Tornect left \
             that as it is."
        ),
        LinkHandler::NotChanged(why) => format!(
            "{INSTALLED}. tornect:// links do not open it: {path} was not changed ({why}). To \
             turn them on, add the line \"{LINK_MIME}={LINK_ENTRY};\" under [Default \
             Applications] in it."
        ),
    }
}

/// What an install says when the installed copy has no lyrebird (`why`):
/// it cannot use obfs4 or Snowflake bridges, which only a network that
/// blocks Tor needs (the final audit before the release).
#[cfg(target_os = "linux")]
pub(crate) fn no_bridges_line(why: &str) -> String {
    format!(
        "The installed copy has no lyrebird ({why}), so it cannot use obfs4 or Snowflake bridges \
         where Tor is blocked. To have them, run tornect install from the unpacked release \
         folder, which holds pt/lyrebird."
    )
}

/// What a Windows install says of lyrebird: the Program Files copy carries
/// none yet (decision M1-88).
#[cfg(any(windows, test))]
pub(crate) const WINDOWS_NO_BRIDGES: &str = "The installed copy has no lyrebird, so it cannot use \
     obfs4 or Snowflake bridges where Tor is blocked; there, run tornect.exe from the unpacked \
     release folder, which holds pt\\lyrebird.exe.";

/// What a Linux uninstall says of a lyrebird it left because its `pt` is a
/// link, not a folder, or a folder other accounts can change: the install
/// never writes there, so the file is not its own.
#[cfg(target_os = "linux")]
fn left_in_folder_line(path: &std::path::Path) -> String {
    format!(
        "{} was left as it is: its folder is a link, not a folder, or can be changed by other \
         accounts, so tornect install did not put it there.",
        path.display()
    )
}

/// What a Linux uninstall says about a `mimeapps.list` that still names the
/// link entry and could not be changed (design `invite` §4.6).
#[cfg(target_os = "linux")]
fn association_left_line(mimeapps: &std::path::Path, why: &str) -> String {
    format!(
        "{} still names Tornect for tornect:// links: it was not changed ({why}).",
        mimeapps.display()
    )
}

/// What a Windows install or uninstall says of a registration of `tornect:`
/// links that is not Tornect's, left as it is (design `invite` §4.6).
#[cfg(any(windows, test))]
fn url_handler_left_line() -> String {
    format!(
        "tornect:// links open another program here (HKEY_CURRENT_USER\\{}); Tornect left that \
         as it is.",
        tornect_platform::install::URL_SCHEME_KEY
    )
}

/// What a Windows install says once it is done, by what it did about
/// `tornect:` links (design `invite` §4.6).
#[cfg(any(windows, test))]
pub(crate) fn windows_installed(
    folder: &str,
    links: tornect_platform::install::WindowsLinks,
) -> String {
    use tornect_platform::install::WindowsLinks;
    match links {
        WindowsLinks::Registered => {
            format!("Tornect is installed in {folder}; tornect:// links open it.")
        }
        WindowsLinks::OtherProgram => {
            format!(
                "Tornect is installed in {folder}. {}",
                url_handler_left_line()
            )
        }
    }
}

/// The start of `uninstall`'s refusal on Windows while administrator access
/// remains (the devices follow).
#[cfg(any(windows, test))]
pub(crate) const REMOVE_ADMIN_FIRST: &str =
    "Remove administrator access first: tornect unattended set-level <device> none";

/// `uninstall`'s refusal on Windows while the grants cannot be read (a store
/// that failed closed): whether a device still has administrator access
/// cannot be told.
#[cfg(any(windows, test))]
pub(crate) const GRANTS_UNREADABLE: &str = "Tornect cannot read its grants now, so it cannot tell \
     whether a device still has administrator access; nothing was removed.";

/// What `uninstall` says where it finds nothing to remove.
pub(crate) const NOTHING_INSTALLED: &str =
    "Tornect is not installed here, and nothing starts it at sign-in; nothing was removed.";

/// What an uninstall run from the installed copy says before its last line:
/// that copy's folder goes at the next restart.
#[cfg(any(windows, test))]
fn at_the_restart_line(folder: &str) -> String {
    format!(
        "Windows removes Tornect's folder ({folder}) at the next restart; until then nothing \
         in this account starts Tornect from it, but another account on this computer can \
         still run it. Install Tornect again only after that restart."
    )
}

/// What `uninstall` says once it is done.
fn removed_line(paths: &Paths) -> String {
    format!(
        "Tornect is removed from this computer. Your pairings and grants stay in {}.",
        paths.state_dir.display()
    )
}

/// What the commands use besides the files; the tests give their own.
pub(crate) struct Deps<'a> {
    /// The offline route's context: its guard runs `install` and `uninstall`,
    /// and its dispatch the start at sign-in (with `autostart` then the
    /// installed copy's backend).
    pub ctx: &'a mut HostContext,
    /// The terminal.
    pub console: &'a mut dyn Console,
    /// Whether a Tornect host holds this home's host lock.
    pub host_running: bool,
    /// The start-at-sign-in backend that would run `spec`
    /// (`tornect_platform::autostart::for_this_os`).
    pub autostart_for: &'a dyn Fn(LaunchSpec) -> Arc<dyn Autostart>,
}

/// What `install` and `uninstall` say, kept where nothing would show it: Windows'
/// Apps and features starts the uninstall entry's command with no console, as do
/// Explorer and the Run box (§B.1.1: the command says what it did or why it
/// refused). Shown at the end in one message box, the error after the lines.
#[cfg(any(windows, test))]
#[derive(Debug, Default)]
struct Collected {
    lines: Vec<String>,
}

#[cfg(any(windows, test))]
impl Collected {
    /// The message box's text: every line in order, then the command's error as
    /// the command line prints it.
    fn text(&self, done: &anyhow::Result<()>) -> String {
        use std::fmt::Write as _;
        let mut text = self.lines.join("\n");
        if let Err(e) = done {
            if !text.is_empty() {
                text.push('\n');
            }
            let _ = write!(text, "{e:#}");
        }
        text
    }
}

#[cfg(any(windows, test))]
impl Console for Collected {
    fn stdout_is_terminal(&self) -> bool {
        false
    }

    fn out(&mut self, line: &str) {
        self.lines.push(line.to_owned());
    }

    /// Never kept: the lines end in a message box, not a terminal, and a
    /// secret is shown only on a terminal (`GENERATED_OFF_TERMINAL`).
    fn secret_line(&mut self, _: &str, _: &str) -> anyhow::Result<()> {
        anyhow::bail!("{}", unattended::GENERATED_OFF_TERMINAL)
    }

    fn err(&mut self, line: &str) {
        self.lines.push(line.to_owned());
    }

    /// Nobody can answer there: as with an input that is not a terminal, no
    /// answer, which every question of these commands takes for no.
    fn ask(&mut self, _: &str) -> Option<String> {
        None
    }
}

/// Run `command` on this process's output, or, where it has none (Windows: a
/// start from Apps and features, Explorer or the Run box), with what it says
/// collected and shown at the end in one message box, its error after the
/// lines (§B.1.1).
#[cfg(windows)]
fn said_somewhere(
    command: impl FnOnce(&mut dyn Console) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    if tornect_platform::win_install::has_output() {
        return command(&mut unattended::Terminal);
    }
    let mut collected = Collected::default();
    let done = command(&mut collected);
    tornect_platform::win_install::show_message(&collected.text(&done), done.is_err());
    done
}

/// The answer to a default-no question: `y` or `yes` (any case) is yes;
/// Enter, any other answer, end of input, a read error or an input that is
/// not a terminal (`None`) is no.
fn default_no(answer: Option<&str>) -> bool {
    answer.is_some_and(|a| matches!(a.trim().to_lowercase().as_str(), "y" | "yes"))
}

/// A guard refusal as the command line words it; a host that started while
/// the dialog was open (the offline route counts it as a live session) is
/// told to be closed.
fn refusal(paths: &Paths, e: &GuardError) -> anyhow::Error {
    if matches!(e, GuardError::RemoteSessionActive)
        && crate::host::HostLock::holder(paths).is_some()
    {
        return anyhow::anyhow!(CLOSE_FIRST);
    }
    match unattended::require_ok(&IpcResponse::fail(0, e.code(), e.to_string())) {
        Err(said) => said,
        Ok(()) => anyhow::anyhow!("{e}"),
    }
}

/// The guard's operation `op`: re-authentication, no remote session for 60 s,
/// its line in `sessions.log`.
#[cfg(target_os = "linux")]
fn authorize(paths: &Paths, ctx: &HostContext, op: &ExternalOp) -> anyhow::Result<()> {
    ctx.guard
        .authorize(Actor::Cli, op)
        .map_err(|e| refusal(paths, &e))
}

/// An install or uninstall that failed after its line: logged again,
/// `ok: false`, with the reason.
fn log_failure(ctx: &HostContext, event: SessionEvent, what: &str, e: &InstallError) {
    let rec = SessionRecord::now(event)
        .by(Actor::Cli)
        .detail(format!("{what} failed"))
        .ok(false)
        .reason(e.to_string());
    if let Err(log_err) = ctx.guard.store().log_event(&rec) {
        tracing::warn!(error = %log_err, "could not log the failed {what}");
    }
}

/// What the sign-in step says of a Tornect host that started while the
/// install ran (`holder`, from the host lock): most likely the window, opened
/// from the menu entry or shortcut the install had just written. It found
/// the unattended store held by this install, so it runs without unattended
/// access until it is started again (a host never retries its store,
/// decision M1-46).
pub(crate) fn opened_meanwhile(holder: &str) -> String {
    format!(
        "Tornect was opened while this install ran ({holder}); it cannot use unattended access \
         until you close it and open it again."
    )
}

/// The refusal of a yes beside that host: the guard counts it as a live
/// session, which is not what happened (audit B21).
fn sign_in_not_set_up(holder: &str, exe: &std::path::Path) -> String {
    format!(
        "{} Start at sign-in was not set up: close Tornect, then run `tornect service \
         install` with the installed copy, {}.",
        opened_meanwhile(holder),
        exe.display()
    )
}

/// The setting's copy, then the question; on a yes, `tornect service
/// install` for the installed copy at `exe`, through its own guard operation
/// (a second dialog, `AutostartChanged` logged). A Tornect host that started
/// meanwhile (the install holds the store until it returns) is named, with
/// what to do: a yes is not tried beside it, and one it refused, having
/// started during the dialog, says so rather than "a remote session is
/// live" (B21).
fn offer_sign_in(deps: &mut Deps<'_>, paths: &Paths, exe: PathBuf) -> anyhow::Result<()> {
    deps.console.out(unattended::TOR_AT_SIGN_IN);
    let yes = default_no(deps.console.ask(SIGN_IN_QUESTION).as_deref());
    if let Some(holder) = crate::host::HostLock::holder(paths) {
        anyhow::ensure!(!yes, sign_in_not_set_up(&holder, &exe));
        deps.console.err(&opened_meanwhile(&holder));
        return Ok(());
    }
    if !yes {
        return Ok(());
    }
    deps.ctx.autostart = (deps.autostart_for)(unattended::launch_spec_for(paths, exe.clone())?);
    let resp = unattended::dispatch(
        deps.ctx,
        IpcRequest {
            id: 1,
            op: IpcOp::ServiceInstall { elevated: false },
        },
    );
    if !resp.ok
        && resp.code == codes::G_REMOTE_SESSION_ACTIVE
        && let Some(holder) = crate::host::HostLock::holder(paths)
    {
        anyhow::bail!(sign_in_not_set_up(&holder, &exe));
    }
    unattended::require_ok(&resp)?;
    if let Some(said) = &resp.detail {
        deps.console.out(&format!("{said}."));
    }
    deps.console.out(unattended::LOGIN_HOST_PINGS_ONLY);
    deps.console.out(unattended::AFTER_LOGIN_ONLY);
    Ok(())
}

/// Whether `backend` has something registered (a status that cannot be read
/// counts: removing an absent registration succeeds).
fn registered(backend: &dyn Autostart) -> bool {
    matches!(backend.status(), Ok(AutostartState::Registered(_)) | Err(_))
}

/// Whether `backend`'s start at sign-in may run the installed copy `exe`: a
/// registration whose command names it (ASCII letters in either case), one
/// whose command cannot be read, or a status that cannot be read (as
/// [`registered`] counts it). Nothing registered, or no mechanism here, is
/// not an earlier install.
#[cfg(any(windows, test))]
fn starts_the_installed_copy(backend: &dyn Autostart, exe: &str) -> bool {
    match backend.status() {
        Ok(AutostartState::Registered(registration)) => match &registration.command {
            Some(command) if !registration.unreadable => command
                .to_ascii_lowercase()
                .contains(&exe.to_ascii_lowercase()),
            _ => true,
        },
        Ok(AutostartState::Absent | AutostartState::Unavailable(_)) => false,
        Err(_) => true,
    }
}

/// `tornect install`.
pub fn install(paths: &Paths) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use anyhow::Context as _;
        // This program, opened before anything else: the copy is read from
        // this handle, which is the running image even if its path changes.
        let mut source =
            std::fs::File::open("/proc/self/exe").context("opening this program to copy it")?;
        // Its own pinned lyrebird, read now from one handle: never a
        // configured path or the developers' folder.
        let bundled = tornect_signal::tor::bundled_lyrebird();
        let lyrebird = match (&bundled, tornect_signal::tor::LYREBIRD_SHA256) {
            (Ok((_, bytes)), Some(pin)) => {
                Ok(tornect_platform::install::PinnedHelper { bytes, sha256: pin })
            }
            (Ok(_), None) => Err("this build pins none".to_owned()),
            (Err(why), _) => Err(why.clone()),
        };
        let host_running = crate::host::HostLock::holder(paths).is_some();
        anyhow::ensure!(!host_running, CLOSE_FIRST);
        let mut ctx = unattended::offline_context(paths)?;
        let files = tornect_platform::install::LinuxInstall::for_this_user()?;
        let mut console = unattended::Terminal;
        let mut deps = Deps {
            ctx: &mut ctx,
            console: &mut console,
            host_running,
            autostart_for: &tornect_platform::autostart::for_this_os,
        };
        install_linux(&mut deps, paths, &files, &mut source, lyrebird)
    }
    #[cfg(windows)]
    {
        said_somewhere(|console| {
            let sys = tornect_platform::install::windows_system()?;
            let host_running = crate::host::HostLock::holder(paths).is_some();
            anyhow::ensure!(!host_running, CLOSE_FIRST);
            let mut ctx = unattended::offline_context(paths)?;
            let custom_home = Paths::platform().ok().as_ref() != Some(paths);
            let mut deps = Deps {
                ctx: &mut ctx,
                console,
                host_running,
                autostart_for: &tornect_platform::autostart::for_this_os,
            };
            install_windows(&mut deps, paths, &*sys, custom_home)
        })
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = paths;
        anyhow::bail!("tornect install is not available on this system yet")
    }
}

/// `tornect uninstall`.
pub fn uninstall(paths: &Paths) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let host_running = crate::host::HostLock::holder(paths).is_some();
        anyhow::ensure!(!host_running, CLOSE_FIRST);
        let mut ctx = unattended::offline_context(paths)?;
        let files = tornect_platform::install::LinuxInstall::for_this_user()?;
        let mut console = unattended::Terminal;
        let mut deps = Deps {
            ctx: &mut ctx,
            console: &mut console,
            host_running,
            autostart_for: &tornect_platform::autostart::for_this_os,
        };
        uninstall_linux(&mut deps, paths, &files)
    }
    #[cfg(windows)]
    {
        said_somewhere(|console| {
            let sys = tornect_platform::install::windows_system()?;
            let host_running = crate::host::HostLock::holder(paths).is_some();
            anyhow::ensure!(!host_running, CLOSE_FIRST);
            let mut ctx = unattended::offline_context(paths)?;
            let mut deps = Deps {
                ctx: &mut ctx,
                console,
                host_running,
                autostart_for: &tornect_platform::autostart::for_this_os,
            };
            uninstall_windows(&mut deps, paths, &*sys)
        })
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = paths;
        anyhow::bail!("tornect uninstall is not available on this system yet")
    }
}

// ---------------------------------------------------------------------------
// Linux
// ---------------------------------------------------------------------------

/// The per-user install as the commands use it: `LinuxInstall`, a fake in
/// the tests.
#[cfg(target_os = "linux")]
pub(crate) trait UserInstall {
    /// The installed executable.
    fn exe(&self) -> PathBuf;
    /// This user's `mimeapps.list`, named in what the commands say.
    fn mimeapps(&self) -> PathBuf;
    /// What `install` checks before writing, writing nothing; `lyrebird`:
    /// whether lyrebird is to be installed too, so its `pt` folder is
    /// checked as well.
    fn preflight(&self, home: Option<&std::path::Path>, lyrebird: bool)
    -> Result<(), InstallError>;
    /// Copy `source` and `lyrebird`, write the menu entry and the link
    /// entry, and name the link entry in `mimeapps.list`: what that last
    /// step did.
    fn install(
        &self,
        source: &mut dyn std::io::Read,
        lyrebird: Option<tornect_platform::install::PinnedHelper<'_>>,
        home: Option<&std::path::Path>,
    ) -> Result<tornect_platform::install::LinkHandler, InstallError>;
    /// Whether anything of an install is there.
    fn installed(&self) -> bool;
    /// Take the link entry out of `mimeapps.list`, remove the menu entry,
    /// the link entry and the copy.
    fn uninstall(&self) -> Result<tornect_platform::install::Removal, InstallError>;
}

#[cfg(target_os = "linux")]
impl UserInstall for tornect_platform::install::LinuxInstall {
    fn exe(&self) -> PathBuf {
        Self::exe(self)
    }

    fn mimeapps(&self) -> PathBuf {
        Self::mimeapps(self)
    }

    fn preflight(
        &self,
        home: Option<&std::path::Path>,
        lyrebird: bool,
    ) -> Result<(), InstallError> {
        Self::preflight(self, home, lyrebird)
    }

    fn install(
        &self,
        source: &mut dyn std::io::Read,
        lyrebird: Option<tornect_platform::install::PinnedHelper<'_>>,
        home: Option<&std::path::Path>,
    ) -> Result<tornect_platform::install::LinkHandler, InstallError> {
        Self::install_with(self, source, lyrebird, home)
    }

    fn installed(&self) -> bool {
        Self::installed(self)
    }

    fn uninstall(&self) -> Result<tornect_platform::install::Removal, InstallError> {
        Self::uninstall(self)
    }
}

/// `tornect install` on Linux: refused beside a running host, then the
/// files' checks (no dialog for an install that cannot be made), the guard's
/// operation, the files with the running copy's pinned `lyrebird` (read
/// before the dialog; `Err` says why there is none, and the install goes on
/// and says what that costs), and the offer to start at sign-in.
#[cfg(target_os = "linux")]
pub(crate) fn install_linux(
    deps: &mut Deps<'_>,
    paths: &Paths,
    files: &dyn UserInstall,
    source: &mut dyn std::io::Read,
    lyrebird: Result<tornect_platform::install::PinnedHelper<'_>, String>,
) -> anyhow::Result<()> {
    anyhow::ensure!(!deps.host_running, CLOSE_FIRST);
    let home = unattended::launch_home(paths)?;
    files.preflight(home.as_deref(), lyrebird.is_ok())?;
    authorize(paths, deps.ctx, &ExternalOp::Install)?;
    let links = match files.install(source, lyrebird.as_ref().ok().copied(), home.as_deref()) {
        Ok(links) => links,
        Err(e) => {
            log_failure(deps.ctx, SessionEvent::Installed, "install", &e);
            return Err(e.into());
        }
    };
    deps.console
        .out(&linux_installed(&links, &files.mimeapps()));
    if let Err(why) = &lyrebird {
        deps.console.out(&no_bridges_line(why));
    }
    offer_sign_in(deps, paths, files.exe())
}

/// `tornect uninstall` on Linux: refused beside a running host; nothing to
/// remove asks nothing; else the guard's operation, then the start at
/// sign-in (whatever copy it runs), the link entry's association in
/// `mimeapps.list`, the menu entry, the link entry and the copy.
#[cfg(target_os = "linux")]
pub(crate) fn uninstall_linux(
    deps: &mut Deps<'_>,
    paths: &Paths,
    files: &dyn UserInstall,
) -> anyhow::Result<()> {
    anyhow::ensure!(!deps.host_running, CLOSE_FIRST);
    let sign_in = (deps.autostart_for)(LaunchSpec {
        exe: files.exe(),
        home: unattended::launch_home(paths)?,
    });
    let starts = registered(&*sign_in);
    if !starts && !files.installed() {
        deps.console.out(NOTHING_INSTALLED);
        return Ok(());
    }
    authorize(paths, deps.ctx, &ExternalOp::Uninstall)?;
    let removed = if starts {
        sign_in
            .uninstall()
            .map(drop)
            .map_err(|e| InstallError::Failed(e.to_string()))
    } else {
        Ok(())
    }
    .and_then(|()| files.uninstall());
    let removal = match removed {
        Ok(removal) => removal,
        Err(e) => {
            log_failure(deps.ctx, SessionEvent::Uninstalled, "uninstall", &e);
            return Err(e.into());
        }
    };
    for path in removal.left {
        deps.console.out(&format!(
            "{} is not a regular file, so it was left as it is.",
            path.display()
        ));
    }
    for path in removal.left_in_folder {
        deps.console.out(&left_in_folder_line(&path));
    }
    if let tornect_platform::install::Association::Left(why) = &removal.association {
        deps.console
            .out(&association_left_line(&files.mimeapps(), why));
    }
    deps.console.out(&removed_line(paths));
    Ok(())
}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

/// Why `install` refuses a custom home on Windows: the rule of
/// [`tornect_platform::autostart::WINDOWS_HOME_RULE`].
#[cfg(any(windows, test))]
fn windows_install_home_refusal() -> String {
    format!(
        "{}; run `tornect install` without it",
        tornect_platform::autostart::WINDOWS_HOME_RULE
    )
}

/// `tornect install` on Windows: refused with a custom home, beside a
/// running host and while a start at sign-in may run an earlier install's
/// copy; then the Program Files steps with the guard's operation between
/// the held, hashed source and the first change, the line that says what
/// `tornect:` links open, and the offer to start at sign-in for the
/// installed copy.
#[cfg(any(windows, test))]
pub(crate) fn install_windows(
    deps: &mut Deps<'_>,
    paths: &Paths,
    sys: &dyn tornect_platform::install::WindowsSystem,
    custom_home: bool,
) -> anyhow::Result<()> {
    anyhow::ensure!(!custom_home, windows_install_home_refusal());
    anyhow::ensure!(!deps.host_running, CLOSE_FIRST);
    // An earlier install's start at sign-in, before anything is asked: the
    // steps below read its program and its entries, not the task.
    let folder = format!(
        "{}\\{}",
        sys.program_files()?.trim_end_matches('\\'),
        tornect_platform::install::WINDOWS_FOLDER
    );
    let exe = format!("{folder}\\{}", tornect_platform::install::WINDOWS_EXE);
    let sign_in = (deps.autostart_for)(LaunchSpec {
        exe: PathBuf::from(&exe),
        home: None,
    });
    anyhow::ensure!(
        !starts_the_installed_copy(&*sign_in, &exe),
        tornect_platform::install::already_installed(&folder)
    );
    let guard = Arc::clone(&deps.ctx.guard);
    let refused = std::cell::RefCell::new(None);
    let authorized = std::cell::Cell::new(false);
    let done = tornect_platform::install::install_in_program_files(sys, &mut || {
        guard_step(&guard, &ExternalOp::Install, &refused, &authorized)
    });
    if let Some(e) = refused.take() {
        return Err(refusal(paths, &e));
    }
    let installed = match done {
        Ok(installed) => installed,
        Err(e) => {
            if authorized.get() {
                log_failure(deps.ctx, SessionEvent::Installed, "install", &e);
            }
            return Err(e.into());
        }
    };
    deps.console
        .out(&windows_installed(&installed.folder, installed.links));
    deps.console.out(WINDOWS_NO_BRIDGES);
    offer_sign_in(deps, paths, PathBuf::from(installed.exe))
}

/// The guard's operation inside the Program Files steps: a refusal is kept
/// in `refused` for the command line's wording; `authorized` once it passed.
#[cfg(any(windows, test))]
fn guard_step(
    guard: &tornect_core::unattended::guard::MutationGuard,
    op: &ExternalOp,
    refused: &std::cell::RefCell<Option<GuardError>>,
    authorized: &std::cell::Cell<bool>,
) -> Result<(), InstallError> {
    match guard.authorize(Actor::Cli, op) {
        Ok(()) => {
            authorized.set(true);
            Ok(())
        }
        Err(e) => {
            let said = e.to_string();
            *refused.borrow_mut() = Some(e);
            Err(InstallError::Refused(said))
        }
    }
}

/// `uninstall`'s refusal while administrator access remains: the grants that
/// hold the level, by label, or the administrator helper task that is still
/// registered; and while the grants cannot be read (a store that failed
/// closed). Where unattended access was never enabled no grant can exist,
/// and the uninstall goes on.
#[cfg(any(windows, test))]
fn admin_access_left(ctx: &HostContext) -> Option<String> {
    if matches!(
        ctx.guard.store().status(),
        tornect_core::unattended::store::StoreStatus::FailedClosed(_)
    ) {
        return Some(GRANTS_UNREADABLE.to_owned());
    }
    let held: Vec<String> = ctx
        .guard
        .store()
        .grants()
        .into_iter()
        .filter(|g| g.holds_level())
        .map(|g| g.label)
        .collect();
    if !held.is_empty() {
        return Some(format!(
            "{REMOVE_ADMIN_FIRST} ({} {} administrator access).",
            held.join(", "),
            if held.len() == 1 { "holds" } else { "hold" }
        ));
    }
    ctx.facts.helper_task().counts().then(|| {
        format!(
            "{REMOVE_ADMIN_FIRST} (no grant holds it any more, but the administrator helper task \
             is still registered: Tornect removes it the next time you sign in here)."
        )
    })
}

/// `tornect uninstall` on Windows: refused beside a running host, while
/// administrator access remains and while the grants cannot be read; then
/// the Program Files steps, with the guard's operation and the removal of the
/// start at sign-in (whatever copy it runs) between the checks and the first
/// change. A registration of `tornect:` links that is not Tornect's, left
/// as it is, is named first, even where nothing else was there. Run from the
/// installed copy, it then says that the folder goes at the next restart.
#[cfg(any(windows, test))]
pub(crate) fn uninstall_windows(
    deps: &mut Deps<'_>,
    paths: &Paths,
    sys: &dyn tornect_platform::install::WindowsSystem,
) -> anyhow::Result<()> {
    anyhow::ensure!(!deps.host_running, CLOSE_FIRST);
    if let Some(why) = admin_access_left(deps.ctx) {
        anyhow::bail!(why);
    }
    let program_files = sys.program_files()?;
    let folder = format!(
        "{}\\{}",
        program_files.trim_end_matches('\\'),
        tornect_platform::install::WINDOWS_FOLDER
    );
    let sign_in = (deps.autostart_for)(LaunchSpec {
        exe: PathBuf::from(format!(
            "{folder}\\{}",
            tornect_platform::install::WINDOWS_EXE
        )),
        home: None,
    });
    let guard = Arc::clone(&deps.ctx.guard);
    let refused = std::cell::RefCell::new(None);
    let authorized = std::cell::Cell::new(false);
    let mut remove_sign_in = || -> Result<(), InstallError> {
        guard_step(&guard, &ExternalOp::Uninstall, &refused, &authorized)?;
        if registered(&*sign_in) {
            sign_in
                .uninstall()
                .map_err(|e| InstallError::Failed(e.to_string()))?;
        }
        Ok(())
    };
    // Whether this is the installed copy, read once, before anything is removed:
    // what the uninstall says at its end reads nothing after the removal.
    let from_install = tornect_platform::install::runs_from_install(sys);
    let mut done =
        tornect_platform::install::uninstall_from_program_files(sys, &mut remove_sign_in);
    if let Ok(found) = &done
        && !authorized.get()
    {
        let url_handler_left = found.url_handler_left;
        if !registered(&*sign_in) {
            if url_handler_left {
                deps.console.out(&url_handler_left_line());
            }
            deps.console.out(NOTHING_INSTALLED);
            return Ok(());
        }
        // Nothing in Program Files, but a start at sign-in of some copy.
        done = remove_sign_in().map(|()| tornect_platform::install::WindowsRemoval {
            url_handler_left,
            ..Default::default()
        });
    }
    if let Some(e) = refused.take() {
        return Err(refusal(paths, &e));
    }
    let removed = match done {
        Ok(removed) => removed,
        Err(e) => {
            if authorized.get() {
                log_failure(deps.ctx, SessionEvent::Uninstalled, "uninstall", &e);
            }
            return Err(e.into());
        }
    };
    if removed.url_handler_left {
        deps.console.out(&url_handler_left_line());
    }
    // Run from the installed copy, its folder went to the next restart.
    if removed.folder && matches!(from_install, Ok(true)) {
        deps.console.out(&at_the_restart_line(&folder));
    }
    deps.console.out(&removed_line(paths));
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use tornect_core::id::DeviceId;
    use tornect_core::keystore::FileSecretStore;
    use tornect_core::levels::{
        AccountFacts, FactsSource, FixedFacts, HelperPresence, WindowsFacts,
    };
    use tornect_core::session_log::SessionLog;
    use tornect_core::unattended::clock::SystemClock;
    use tornect_core::unattended::grant::Preset;
    use tornect_core::unattended::guard::{
        AllowAllPaired, MutationGuard, NoSessionActivity, ReAuth, ReAuthError,
        RemoteSessionActivity,
    };
    use tornect_core::unattended::ipc::GrantOptions;
    use tornect_core::unattended::readiness::SharedReadiness;
    use tornect_core::unattended::store::{GrantStore, StoreStatus};
    use tornect_platform::autostart::{AutostartError, Registration};
    use tornect_platform::install::{
        Association, Elevated, HeldImage, LinkHandler, Removal, UrlKey, WindowsLinks, WindowsSystem,
    };

    use super::*;

    /// Re-authentication that records each operation and allows the first
    /// `allow` of them.
    struct Dialogs {
        asked: Mutex<Vec<String>>,
        allow: usize,
        /// While the dialog of this operation is up, a Tornect host starts
        /// for this home (it takes the host lock, held from then on).
        host_starts: Mutex<Option<(&'static str, Paths)>>,
        host: Mutex<Option<crate::host::HostLock>>,
    }

    impl Dialogs {
        fn allowing(allow: usize) -> Arc<Self> {
            Arc::new(Self {
                asked: Mutex::new(Vec::new()),
                allow,
                host_starts: Mutex::new(None),
                host: Mutex::new(None),
            })
        }

        fn asked(&self) -> Vec<String> {
            self.asked.lock().unwrap().clone()
        }
    }

    impl ReAuth for Dialogs {
        fn reauthenticate(&self, op: &str) -> Result<(), ReAuthError> {
            if let Some((during, paths)) = &*self.host_starts.lock().unwrap()
                && *during == op
            {
                *self.host.lock().unwrap() = Some(crate::host::HostLock::acquire(paths).unwrap());
            }
            let mut asked = self.asked.lock().unwrap();
            asked.push(op.to_owned());
            if asked.len() <= self.allow {
                Ok(())
            } else {
                Err(ReAuthError::Denied)
            }
        }
    }

    /// A start-at-sign-in backend that records what it runs and what it is
    /// asked.
    #[derive(Default)]
    struct FakeSignIn {
        spec: Option<LaunchSpec>,
        state: Mutex<Option<AutostartState>>,
        installs: Mutex<usize>,
        uninstalls: Mutex<usize>,
        /// Its status cannot be read.
        unreadable: bool,
    }

    impl Autostart for FakeSignIn {
        fn preflight(&self, _elevated: bool) -> Result<(), AutostartError> {
            Ok(())
        }

        fn install(&self, elevated: bool) -> Result<AutostartState, AutostartError> {
            *self.installs.lock().unwrap() += 1;
            let state = AutostartState::Registered(Registration {
                enabled: true,
                elevated,
                command: self
                    .spec
                    .as_ref()
                    .map(|s| format!("\"{}\" \"--background\"", s.exe.display())),
                note: None,
                unreadable: false,
            });
            *self.state.lock().unwrap() = Some(state.clone());
            Ok(state)
        }

        fn uninstall(&self) -> Result<AutostartState, AutostartError> {
            *self.uninstalls.lock().unwrap() += 1;
            *self.state.lock().unwrap() = None;
            Ok(AutostartState::Absent)
        }

        fn status(&self) -> Result<AutostartState, AutostartError> {
            if self.unreadable {
                return Err(AutostartError::Failed(
                    "the test's status cannot be read".to_owned(),
                ));
            }
            Ok(self
                .state
                .lock()
                .unwrap()
                .clone()
                .unwrap_or(AutostartState::Absent))
        }

        fn describe(&self) -> String {
            "the test's start at sign-in".to_owned()
        }

        fn manual_removal(&self) -> String {
            "remove it as the test says".to_owned()
        }
    }

    /// Every backend the command asked for, by the spec it runs.
    #[derive(Default)]
    struct Backends {
        made: Mutex<Vec<Arc<FakeSignIn>>>,
        /// What a new backend finds registered.
        registered: Option<AutostartState>,
        /// Whether a new backend's status cannot be read.
        unreadable: bool,
    }

    impl Backends {
        fn make(&self, spec: LaunchSpec) -> Arc<dyn Autostart> {
            let backend = Arc::new(FakeSignIn {
                spec: Some(spec),
                state: Mutex::new(self.registered.clone()),
                unreadable: self.unreadable,
                ..FakeSignIn::default()
            });
            self.made.lock().unwrap().push(Arc::clone(&backend));
            backend
        }

        fn specs(&self) -> Vec<LaunchSpec> {
            self.made
                .lock()
                .unwrap()
                .iter()
                .filter_map(|b| b.spec.clone())
                .collect()
        }

        fn installs(&self) -> usize {
            self.made
                .lock()
                .unwrap()
                .iter()
                .map(|b| *b.installs.lock().unwrap())
                .sum()
        }
    }

    /// A scripted terminal: the answers to give, and every line in order.
    struct Script {
        answers: VecDeque<Option<String>>,
        lines: Vec<String>,
    }

    impl Script {
        fn answering(answers: &[Option<&str>]) -> Self {
            Self {
                answers: answers.iter().map(|a| a.map(str::to_owned)).collect(),
                lines: Vec::new(),
            }
        }

        fn said(&self, line: &str) -> bool {
            self.lines.iter().any(|l| l == &format!("out: {line}"))
        }
    }

    impl Console for Script {
        fn stdout_is_terminal(&self) -> bool {
            true
        }

        fn out(&mut self, line: &str) {
            self.lines.push(format!("out: {line}"));
        }

        fn secret_line(&mut self, prefix: &str, secret: &str) -> anyhow::Result<()> {
            self.lines.push(format!("secret: {prefix}{secret}"));
            Ok(())
        }

        fn err(&mut self, line: &str) {
            self.lines.push(format!("err: {line}"));
        }

        fn ask(&mut self, question: &str) -> Option<String> {
            self.lines.push(format!("ask: {question}"));
            self.answers.pop_front().flatten()
        }
    }

    /// The per-user install over a folder of the test's: it writes the
    /// executable only, and records what it was asked; `links` and
    /// `association` are what its `mimeapps.list` steps answer.
    struct FakeFiles {
        dir: PathBuf,
        homes: Mutex<Vec<Option<PathBuf>>>,
        fail: Option<&'static str>,
        links: LinkHandler,
        association: Association,
        /// The lyrebird each install was handed.
        lyrebirds: Mutex<Vec<Option<Vec<u8>>>>,
        /// Whether each preflight was told lyrebird goes too.
        preflight_lyrebird: Mutex<Vec<bool>>,
        /// What the uninstall leaves in a `pt` that is not its own.
        left_in_folder: Vec<PathBuf>,
    }

    impl UserInstall for FakeFiles {
        fn exe(&self) -> PathBuf {
            self.dir.join("tornect")
        }

        fn mimeapps(&self) -> PathBuf {
            self.dir.join("config").join("mimeapps.list")
        }

        fn preflight(
            &self,
            home: Option<&std::path::Path>,
            lyrebird: bool,
        ) -> Result<(), InstallError> {
            self.homes.lock().unwrap().push(home.map(PathBuf::from));
            self.preflight_lyrebird.lock().unwrap().push(lyrebird);
            Ok(())
        }

        fn install(
            &self,
            source: &mut dyn std::io::Read,
            lyrebird: Option<tornect_platform::install::PinnedHelper<'_>>,
            _home: Option<&std::path::Path>,
        ) -> Result<LinkHandler, InstallError> {
            self.lyrebirds
                .lock()
                .unwrap()
                .push(lyrebird.map(|l| l.bytes.to_vec()));
            if let Some(why) = self.fail {
                return Err(InstallError::Failed(why.to_owned()));
            }
            let mut bytes = Vec::new();
            source.read_to_end(&mut bytes).unwrap();
            std::fs::write(self.exe(), bytes).unwrap();
            Ok(self.links.clone())
        }

        fn installed(&self) -> bool {
            self.exe().exists()
        }

        fn uninstall(&self) -> Result<Removal, InstallError> {
            let mut removal = Removal {
                association: self.association.clone(),
                left_in_folder: self.left_in_folder.clone(),
                ..Removal::default()
            };
            if self.exe().exists() {
                std::fs::remove_file(self.exe()).unwrap();
                removal.removed.push(self.exe());
            }
            Ok(removal)
        }
    }

    /// Windows that must not be asked anything.
    struct Untouched;

    impl WindowsSystem for Untouched {
        fn program_files(&self) -> Result<String, InstallError> {
            panic!("asked for Program Files")
        }
        fn system_directory(&self) -> Result<String, InstallError> {
            panic!("asked for the system folder")
        }
        fn start_menu_programs(&self) -> Result<String, InstallError> {
            panic!("asked for the Start menu")
        }
        fn open_own_image(&self) -> Result<Box<dyn HeldImage + '_>, InstallError> {
            panic!("opened the image")
        }
        fn folder_entries(&self, _: &str) -> Result<Option<Vec<String>>, InstallError> {
            panic!("read a folder")
        }
        fn is_reparse_point(&self, _: &str) -> Result<bool, InstallError> {
            panic!("read a folder")
        }
        fn read_file(&self, _: &str) -> Result<Box<dyn std::io::Read + '_>, InstallError> {
            panic!("read a file")
        }
        fn security(
            &self,
            _: &str,
        ) -> Result<tornect_platform::helper_task::Security, InstallError> {
            panic!("read an ACL")
        }
        fn elevated_program(&self, _: &Elevated) -> String {
            panic!("asked for a program")
        }
        fn run_elevated(&self, _: &Elevated) -> Result<(), InstallError> {
            panic!("ran a step elevated")
        }
        fn uninstall_entry_exists(&self, _: &str) -> Result<bool, InstallError> {
            panic!("read the registry")
        }
        fn file_exists(&self, _: &str) -> Result<bool, InstallError> {
            panic!("read a file")
        }
        fn pending_removals(&self) -> Result<Vec<String>, InstallError> {
            panic!("read the registry")
        }
        fn own_path(&self) -> Result<String, InstallError> {
            panic!("read the image's path")
        }
        fn write_shortcut(&self, _: &str, _: &str) -> Result<(), InstallError> {
            panic!("wrote a shortcut")
        }
        fn remove_shortcut(&self, _: &str) -> Result<(), InstallError> {
            panic!("removed a shortcut")
        }
        fn url_handler(&self) -> Result<UrlKey, InstallError> {
            panic!("read the link registration")
        }
        fn write_url_handler(&self, _: &str) -> Result<(), InstallError> {
            panic!("wrote the link registration")
        }
        fn remove_url_handler(&self) -> Result<(), InstallError> {
            panic!("removed the link registration")
        }
    }

    /// Windows with nothing of Tornect on it, whose image cannot be opened:
    /// an install that goes on stops there, before anything is asked.
    struct Bare;

    /// Why [`Bare`]'s install stops.
    const BARE_IMAGE: &str = "the test's image cannot be opened";

    impl WindowsSystem for Bare {
        fn program_files(&self) -> Result<String, InstallError> {
            Ok("C:\\Program Files".to_owned())
        }
        fn system_directory(&self) -> Result<String, InstallError> {
            Ok("C:\\Windows\\System32".to_owned())
        }
        fn start_menu_programs(&self) -> Result<String, InstallError> {
            Ok("C:\\Users\\u\\Start Menu\\Programs".to_owned())
        }
        fn open_own_image(&self) -> Result<Box<dyn HeldImage + '_>, InstallError> {
            Err(InstallError::Failed(BARE_IMAGE.to_owned()))
        }
        fn folder_entries(&self, _: &str) -> Result<Option<Vec<String>>, InstallError> {
            Ok(None)
        }
        fn is_reparse_point(&self, _: &str) -> Result<bool, InstallError> {
            Ok(false)
        }
        fn read_file(&self, _: &str) -> Result<Box<dyn std::io::Read + '_>, InstallError> {
            panic!("read a file")
        }
        fn security(
            &self,
            _: &str,
        ) -> Result<tornect_platform::helper_task::Security, InstallError> {
            panic!("read an ACL")
        }
        fn elevated_program(&self, _: &Elevated) -> String {
            panic!("asked for a program")
        }
        fn run_elevated(&self, _: &Elevated) -> Result<(), InstallError> {
            panic!("ran a step elevated")
        }
        fn uninstall_entry_exists(&self, _: &str) -> Result<bool, InstallError> {
            Ok(false)
        }
        fn file_exists(&self, _: &str) -> Result<bool, InstallError> {
            Ok(false)
        }
        fn pending_removals(&self) -> Result<Vec<String>, InstallError> {
            Ok(Vec::new())
        }
        fn own_path(&self) -> Result<String, InstallError> {
            Ok("C:\\Users\\u\\Downloads\\tornect\\tornect.exe".to_owned())
        }
        fn write_shortcut(&self, _: &str, _: &str) -> Result<(), InstallError> {
            panic!("wrote a shortcut")
        }
        fn remove_shortcut(&self, _: &str) -> Result<(), InstallError> {
            panic!("removed a shortcut")
        }
        fn url_handler(&self) -> Result<UrlKey, InstallError> {
            Ok(UrlKey::Absent)
        }
        fn write_url_handler(&self, _: &str) -> Result<(), InstallError> {
            panic!("wrote the link registration")
        }
        fn remove_url_handler(&self) -> Result<(), InstallError> {
            panic!("removed the link registration")
        }
    }

    struct Env {
        tmp: tempfile::TempDir,
        paths: Paths,
        ctx: HostContext,
        dialogs: Arc<Dialogs>,
        files: FakeFiles,
    }

    /// The offline route's context over a store of its own in a temporary
    /// home, on `facts`, with re-authentication allowed `allow` times.
    fn env(facts: FixedFacts, allow: usize) -> Env {
        env_with(facts, allow, |_| {})
    }

    /// [`env`], with `before_open` run on the home before its store opens.
    fn env_with(facts: FixedFacts, allow: usize, before_open: impl FnOnce(&Paths)) -> Env {
        env_full(facts, allow, before_open, |_| Arc::new(NoSessionActivity))
    }

    /// [`env`] whose guard sees a running Tornect host as a live session,
    /// as the offline route's does (`HostLockActivity`).
    fn env_seeing_hosts(facts: FixedFacts, allow: usize) -> Env {
        env_full(facts, allow, |_| {}, unattended::offline_activity)
    }

    /// [`env_with`], the guard's view of remote sessions from `activity`.
    fn env_full(
        facts: FixedFacts,
        allow: usize,
        before_open: impl FnOnce(&Paths),
        activity: impl FnOnce(&Paths) -> Arc<dyn RemoteSessionActivity>,
    ) -> Env {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path().join("home"));
        paths.ensure().unwrap();
        before_open(&paths);
        let bin = tmp.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let secrets = Arc::new(FileSecretStore::open(paths.keys_dir()).unwrap());
        let log = SessionLog::new(paths.sessions_log());
        let store = GrantStore::open(
            &paths,
            secrets as Arc<dyn tornect_core::SecretStore>,
            Arc::new(SystemClock::default()),
            log.clone(),
        )
        .unwrap();
        let facts: Arc<dyn FactsSource> = Arc::new(facts);
        let dialogs = Dialogs::allowing(allow);
        let guard = MutationGuard::new(
            store,
            Arc::clone(&dialogs) as Arc<dyn ReAuth>,
            activity(&paths),
            Arc::clone(&facts),
        )
        .with_paired_devices(Arc::new(AllowAllPaired))
        .with_server_setup_source(Arc::new(
            tornect_signal::unattended::OpaqueServerSetupSource,
        ));
        let ctx = HostContext {
            guard: Arc::new(guard),
            host_onion_pk: [0x42; 32],
            readiness: SharedReadiness::default(),
            autostart: Arc::new(tornect_platform::autostart::NoAutostart("test".to_owned())),
            user_inputs: Vec::new(),
            kill: None,
            log,
            facts,
            show: None,
            indicator: None,
        };
        Env {
            tmp,
            paths,
            ctx,
            dialogs,
            files: FakeFiles {
                dir: bin,
                homes: Mutex::new(Vec::new()),
                fail: None,
                links: LinkHandler::Registered,
                association: Association::NotThere,
                lyrebirds: Mutex::new(Vec::new()),
                preflight_lyrebird: Mutex::new(Vec::new()),
                left_in_folder: Vec::new(),
            },
        }
    }

    fn linux_env(allow: usize) -> Env {
        env(FixedFacts::linux(), allow)
    }

    /// An installed copy on a Windows administrator account, where grants
    /// can hold the administrator level.
    fn windows_admin_account() -> AccountFacts {
        AccountFacts::Windows(WindowsFacts {
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

    /// [`windows_admin_account`] without the administrator helper task.
    fn windows_admin() -> FixedFacts {
        FixedFacts::new(windows_admin_account(), HelperPresence::Absent)
    }

    /// The event names of `sessions.log`, with each line's `detail` and `ok`.
    fn lines(env: &Env) -> Vec<(SessionEvent, Option<String>, Option<bool>)> {
        env.ctx
            .log
            .read_all()
            .unwrap()
            .into_iter()
            .map(|r| (r.event, r.detail, r.ok))
            .collect()
    }

    impl Env {
        /// `tornect install` on Linux with the scripted answers.
        fn install(
            &mut self,
            answers: &[Option<&str>],
            backends: &Backends,
        ) -> (anyhow::Result<()>, Script) {
            let mut script = Script::answering(answers);
            let make = |spec| backends.make(spec);
            let mut deps = Deps {
                ctx: &mut self.ctx,
                console: &mut script,
                host_running: false,
                autostart_for: &make,
            };
            let done = install_linux(
                &mut deps,
                &self.paths,
                &self.files,
                &mut std::io::Cursor::new(b"the program".to_vec()),
                Err(NO_LYREBIRD_HERE.to_owned()),
            );
            (done, script)
        }

        /// `tornect uninstall` on Linux, the start at sign-in from `make`.
        fn uninstall(
            &mut self,
            make: &dyn Fn(LaunchSpec) -> Arc<dyn Autostart>,
        ) -> (anyhow::Result<()>, Script) {
            let mut script = Script::answering(&[]);
            let mut deps = Deps {
                ctx: &mut self.ctx,
                console: &mut script,
                host_running: false,
                autostart_for: make,
            };
            let done = uninstall_linux(&mut deps, &self.paths, &self.files);
            (done, script)
        }
    }

    /// Why the tests' copy has no lyrebird to install.
    const NO_LYREBIRD_HERE: &str = "none beside this test's copy";

    /// The final audit before the release: the running copy's pinned
    /// lyrebird goes with the install, and the install says nothing more;
    /// without one it goes on and says, after its own line, that the
    /// installed copy cannot use obfs4 or Snowflake bridges, and why.
    #[test]
    fn the_install_carries_lyrebird_or_says_what_its_absence_costs() {
        const BYTES: &[u8] = b"the bridge helper";
        let pin = "0".repeat(64);
        for lyrebird in [
            Ok(tornect_platform::install::PinnedHelper {
                bytes: BYTES,
                sha256: &pin,
            }),
            Err(NO_LYREBIRD_HERE.to_owned()),
        ] {
            let with = lyrebird.is_ok();
            let mut env = linux_env(2);
            let backends = Backends::default();
            let make = |spec| backends.make(spec);
            let mut script = Script::answering(&[Some("\n")]);
            let mut deps = Deps {
                ctx: &mut env.ctx,
                console: &mut script,
                host_running: false,
                autostart_for: &make,
            };
            install_linux(
                &mut deps,
                &env.paths,
                &env.files,
                &mut std::io::Cursor::new(b"the program".to_vec()),
                lyrebird,
            )
            .unwrap();
            assert_eq!(
                *env.files.lyrebirds.lock().unwrap(),
                [with.then(|| BYTES.to_vec())]
            );
            // The security review of the final pass: the checks before the
            // dialog include lyrebird's `pt` folder whenever it goes too.
            assert_eq!(*env.files.preflight_lyrebird.lock().unwrap(), [with]);
            let line = no_bridges_line(NO_LYREBIRD_HERE);
            assert_eq!(script.said(&line), !with, "{:?}", script.lines);
            assert!(
                line.contains("cannot use obfs4 or Snowflake bridges"),
                "{line}"
            );
            let installed = script
                .lines
                .iter()
                .position(|l| {
                    *l == format!(
                        "out: {}",
                        linux_installed(&LinkHandler::Registered, &env.files.mimeapps())
                    )
                })
                .unwrap();
            if !with {
                assert_eq!(script.lines[installed + 1], format!("out: {line}"));
            }
        }
    }

    /// The final audit before the release: what the install puts beside the
    /// installed copy is what that copy's own lyrebird lookup finds and
    /// accepts (beside it in `pt/`, the pin, not writable by others), read
    /// from a release folder's `pt/lyrebird` as `install` reads it.
    #[test]
    fn an_installed_copy_finds_the_lyrebird_its_install_put_beside_it() {
        use std::os::unix::fs::PermissionsExt as _;
        use tornect_signal::tor::bundled_lyrebird_in;
        const BYTES: &[u8] = b"\x7fELF the bridge helper";
        let tmp = tempfile::tempdir().unwrap();
        let release = tmp.path().join("release");
        std::fs::create_dir_all(release.join("pt")).unwrap();
        let shipped = release.join("pt").join("lyrebird");
        std::fs::write(&shipped, BYTES).unwrap();
        std::fs::set_permissions(&shipped, std::fs::Permissions::from_mode(0o755)).unwrap();
        let pin = tornect_platform::install::sha256_hex(BYTES);
        let (_, bytes) = bundled_lyrebird_in(Some(&release), Some(&pin)).unwrap();
        let files = tornect_platform::install::LinuxInstall::new(
            tmp.path().join("bin"),
            tmp.path().join("apps"),
            tmp.path().join("config"),
        );
        assert!(bundled_lyrebird_in(Some(&tmp.path().join("bin")), Some(&pin)).is_err());
        files
            .install_with(
                &mut std::io::Cursor::new(b"the program".to_vec()),
                Some(tornect_platform::install::PinnedHelper {
                    bytes: &bytes,
                    sha256: &pin,
                }),
                None,
            )
            .unwrap();
        assert_eq!(
            bundled_lyrebird_in(Some(&tmp.path().join("bin")), Some(&pin)),
            Ok((files.lyrebird(), BYTES.to_vec()))
        );
        // The security review of the final pass: the user's own unpinned
        // lyrebird in the bin folder, which the lookup tries first, is
        // passed over for the pinned one the install wrote, not a shadow
        // that fails every bridged rung.
        let own = tmp.path().join("bin").join(tornect_signal::tor::LYREBIRD);
        std::fs::write(&own, b"\x7fELF the user's own build").unwrap();
        std::fs::set_permissions(&own, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            bundled_lyrebird_in(Some(&tmp.path().join("bin")), Some(&pin)),
            Ok((files.lyrebird(), BYTES.to_vec()))
        );
        files.uninstall().unwrap();
        assert!(!files.pt_dir().exists());
        assert!(own.exists(), "never the install's to remove");
    }

    /// §B.1.1: after the install, "Start Tornect when I sign in? [y/N]":
    /// Enter, no, anything else, end of input or no terminal registers
    /// nothing; `y` or `yes` (any case) registers.
    #[test]
    fn install_offers_start_at_sign_in_and_defaults_to_no() {
        for answer in [Some("\n"), None, Some("no\n"), Some("maybe\n")] {
            let mut env = linux_env(2);
            let backends = Backends::default();
            let (done, script) = env.install(&[answer], &backends);
            done.unwrap();
            assert!(
                script.said(&linux_installed(
                    &LinkHandler::Registered,
                    &env.files.mimeapps()
                )),
                "{answer:?}: {:?}",
                script.lines
            );
            assert!(
                script.lines.contains(&format!("ask: {SIGN_IN_QUESTION}")),
                "{:?}",
                script.lines
            );
            assert_eq!(backends.installs(), 0, "{answer:?} registered");
            assert_eq!(env.dialogs.asked(), ["install"], "{answer:?}");
        }
        for answer in ["y\n", "YES\n"] {
            let mut env = linux_env(2);
            let backends = Backends::default();
            let (done, _) = env.install(&[Some(answer)], &backends);
            done.unwrap();
            assert_eq!(backends.installs(), 1, "{answer:?}");
        }
        assert_eq!(SIGN_IN_QUESTION, "Start Tornect when I sign in? [y/N]");
    }

    /// Design `invite` §4.6: the install's line says, word for word, what
    /// `tornect:` links do after its `mimeapps.list` step; the install
    /// succeeds whatever that step did.
    #[test]
    fn the_install_says_what_links_do() {
        let path = std::path::Path::new("/home/u/.config/mimeapps.list");
        let why = "it is a link to another file, which Tornect never writes through";
        for (links, line) in [
            (
                LinkHandler::Registered,
                "Tornect is installed in ~/.local/bin, with a menu entry; tornect:// links open \
                 it."
                .to_owned(),
            ),
            (
                LinkHandler::OtherDefault,
                "Tornect is installed in ~/.local/bin, with a menu entry. tornect:// links open \
                 another program here (/home/u/.config/mimeapps.list says so); Tornect left that \
                 as it is."
                    .to_owned(),
            ),
            (
                LinkHandler::TurnedOff,
                "Tornect is installed in ~/.local/bin, with a menu entry. tornect:// links are \
                 turned off for Tornect in /home/u/.config/mimeapps.list; Tornect left that as it \
                 is."
                .to_owned(),
            ),
            (
                LinkHandler::NotChanged(why.to_owned()),
                format!(
                    "Tornect is installed in ~/.local/bin, with a menu entry. tornect:// links do \
                     not open it: /home/u/.config/mimeapps.list was not changed ({why}). To turn \
                     them on, add the line \"x-scheme-handler/tornect=tornect-link.desktop;\" \
                     under [Default Applications] in it."
                ),
            ),
        ] {
            assert_eq!(linux_installed(&links, path), line);
            let mut env = linux_env(2);
            env.files.links = links.clone();
            let backends = Backends::default();
            let (done, script) = env.install(&[None], &backends);
            done.unwrap();
            let said = linux_installed(&links, &env.files.mimeapps());
            assert!(script.said(&said), "{links:?}: {:?}", script.lines);
            assert!(env.files.installed(), "{links:?}");
        }
    }

    /// The security review of the final pass: a lyrebird the uninstall left
    /// in a `pt` that is not its own (a link, or a folder others can change)
    /// is named, with why.
    #[test]
    fn the_uninstall_names_a_lyrebird_it_left_in_a_folder_not_its_own() {
        let mut env = linux_env(4);
        let backends = Backends::default();
        env.install(&[None], &backends).0.unwrap();
        let left = env.files.dir.join("pt").join("lyrebird");
        env.files.left_in_folder = vec![left.clone()];
        let (done, script) = env.uninstall(&|spec| backends.make(spec));
        done.unwrap();
        let line = left_in_folder_line(&left);
        assert!(line.starts_with(&format!("{} was left as it is", left.display())));
        assert!(script.said(&line), "{:?}", script.lines);
    }

    /// Design `invite` §4.6: an uninstall that could not take the link entry
    /// out of a `mimeapps.list` that still names it says so, before its last
    /// line; one that took it out, or found nothing, says nothing of it.
    #[test]
    fn the_uninstall_says_when_mimeapps_still_names_tornect() {
        let why = "it is a link to another file, which Tornect never writes through";
        for (association, says) in [
            (Association::Left(why.to_owned()), true),
            (Association::Removed, false),
            (Association::NotThere, false),
        ] {
            let mut env = linux_env(4);
            let backends = Backends::default();
            env.install(&[None], &backends).0.unwrap();
            env.files.association = association.clone();
            let (done, script) = env.uninstall(&|spec| backends.make(spec));
            done.unwrap();
            let line = format!(
                "{} still names Tornect for tornect:// links: it was not changed ({why}).",
                env.files.mimeapps().display()
            );
            assert_eq!(
                association_left_line(&env.files.mimeapps(), why),
                line,
                "{association:?}"
            );
            assert_eq!(
                script.said(&line),
                says,
                "{association:?}: {:?}",
                script.lines
            );
            assert!(
                !script
                    .lines
                    .iter()
                    .any(|l| l.contains("still names Tornect"))
                    || says,
                "{association:?}"
            );
            let last = script.lines.last().cloned().unwrap_or_default();
            assert_eq!(
                last,
                format!("out: {}", removed_line(&env.paths)),
                "{association:?}"
            );
        }
    }

    /// A terminal at which, while the sign-in question waits, Tornect is
    /// opened from the menu entry the install has just written: its host
    /// takes the host lock (and finds the store held by the install).
    struct OpenedWhileAsking<'p> {
        script: Script,
        paths: &'p Paths,
        host: Option<crate::host::HostLock>,
    }

    impl Console for OpenedWhileAsking<'_> {
        fn stdout_is_terminal(&self) -> bool {
            true
        }

        fn out(&mut self, line: &str) {
            self.script.out(line);
        }

        fn secret_line(&mut self, prefix: &str, secret: &str) -> anyhow::Result<()> {
            self.script.secret_line(prefix, secret)
        }

        fn err(&mut self, line: &str) {
            self.script.err(line);
        }

        fn ask(&mut self, question: &str) -> Option<String> {
            self.host = Some(crate::host::HostLock::acquire(self.paths).unwrap());
            self.script.ask(question)
        }
    }

    /// B21: Tornect opened from the new menu entry while "Start Tornect when
    /// I sign in?" waits. A yes is refused with what happened and what to do
    /// (close Tornect, then `tornect service install` with the installed
    /// copy), before any dialog, never as "a remote session is live"; a no
    /// says that the Tornect just opened has no unattended access until it
    /// is opened again. The install stays either way.
    #[test]
    fn a_tornect_opened_while_the_sign_in_question_waits_is_named() {
        let pid = format!("pid {}", std::process::id());
        for (answer, yes) in [(Some("y\n"), true), (Some("\n"), false), (None, false)] {
            let mut env = linux_env(2);
            let backends = Backends::default();
            let make = |spec| backends.make(spec);
            let paths = env.paths.clone();
            let mut console = OpenedWhileAsking {
                script: Script::answering(&[answer]),
                paths: &paths,
                host: None,
            };
            let mut deps = Deps {
                ctx: &mut env.ctx,
                console: &mut console,
                host_running: false,
                autostart_for: &make,
            };
            let done = install_linux(
                &mut deps,
                &env.paths,
                &env.files,
                &mut std::io::Cursor::new(b"the program".to_vec()),
                Err(NO_LYREBIRD_HERE.to_owned()),
            );
            assert!(env.files.installed(), "{answer:?}: the install stays");
            assert_eq!(backends.installs(), 0, "{answer:?}");
            assert_eq!(env.dialogs.asked(), ["install"], "{answer:?}: no dialog");
            if yes {
                let err = done.unwrap_err().to_string();
                assert!(err.starts_with(&opened_meanwhile(&pid)), "{err}");
                assert!(
                    err.contains(
                        "Start at sign-in was not set up: close Tornect, then run \
                         `tornect service install` with the installed copy"
                    ) && err.contains(&env.files.exe().display().to_string()),
                    "{err}"
                );
                assert!(!err.contains("remote session"), "{err}");
            } else {
                done.unwrap();
                assert!(
                    console
                        .script
                        .lines
                        .contains(&format!("err: {}", opened_meanwhile(&pid))),
                    "{answer:?}: {:?}",
                    console.script.lines
                );
            }
        }
    }

    /// B21: a Tornect opened while the sign-in's own dialog is up. The
    /// guard counts its host as a live session (the offline route cannot
    /// see its sessions) and refuses; the command line says what happened
    /// instead of "a remote session is live". Failed before the fix.
    #[test]
    fn a_tornect_opened_during_the_sign_in_dialog_is_named() {
        let mut env = env_seeing_hosts(FixedFacts::linux(), 2);
        *env.dialogs.host_starts.lock().unwrap() = Some(("service_install", env.paths.clone()));
        let backends = Backends::default();
        let (done, _) = env.install(&[Some("yes\n")], &backends);
        let err = done.unwrap_err().to_string();
        let pid = format!("pid {}", std::process::id());
        assert!(err.starts_with(&opened_meanwhile(&pid)), "{err}");
        assert!(err.contains("Start at sign-in was not set up"), "{err}");
        assert!(!err.contains("remote session"), "{err}");
        assert_eq!(env.dialogs.asked(), ["install", "service_install"]);
        assert_eq!(backends.installs(), 0);
        assert!(env.files.installed(), "the install stays");
    }

    /// §B.1.1: the setting's copy (Tor at every sign-in) is printed before
    /// the question, from its one constant.
    #[test]
    fn the_sign_in_question_says_tor_connects_at_every_sign_in_first() {
        let mut env = linux_env(2);
        let (done, script) = env.install(&[Some("\n")], &Backends::default());
        done.unwrap();
        let tor = script
            .lines
            .iter()
            .position(|l| *l == format!("out: {}", unattended::TOR_AT_SIGN_IN))
            .unwrap_or_else(|| panic!("{:?}", script.lines));
        let ask = script
            .lines
            .iter()
            .position(|l| *l == format!("ask: {SIGN_IN_QUESTION}"))
            .unwrap();
        assert!(tor < ask, "{:?}", script.lines);
        assert_eq!(ask, script.lines.len() - 1, "{:?}", script.lines);
    }

    /// A yes registers the installed copy, never the program that ran the
    /// install: the backend runs the copy's path, with this home.
    #[test]
    fn the_sign_in_start_runs_the_installed_copy() {
        let mut env = linux_env(2);
        let backends = Backends::default();
        let (done, script) = env.install(&[Some("y\n")], &backends);
        done.unwrap();
        let home = std::fs::canonicalize(&env.paths.config_dir).unwrap();
        assert_eq!(
            backends.specs(),
            [LaunchSpec {
                exe: env.files.exe(),
                home: Some(home.clone()),
            }]
        );
        assert_ne!(Some(env.files.exe()), std::env::current_exe().ok());
        // The menu entry gets the same home (`--home`, absolute).
        assert_eq!(*env.files.homes.lock().unwrap(), [Some(home)]);
        assert!(
            script.said(unattended::LOGIN_HOST_PINGS_ONLY),
            "{:?}",
            script.lines
        );
        assert!(
            script.said(unattended::AFTER_LOGIN_ONLY),
            "{:?}",
            script.lines
        );
    }

    /// The yes is a guard operation of its own: a second dialog, its own
    /// `autostart_changed` line after the install's `installed` line; when
    /// that dialog is refused, the install stays and nothing starts at
    /// sign-in.
    #[test]
    fn yes_runs_its_own_guard_operation() {
        let mut env = linux_env(2);
        let backends = Backends::default();
        let (done, _) = env.install(&[Some("yes\n")], &backends);
        done.unwrap();
        assert_eq!(env.dialogs.asked(), ["install", "service_install"]);
        let logged: Vec<_> = lines(&env)
            .into_iter()
            .filter(|(e, ..)| matches!(e, SessionEvent::Installed | SessionEvent::AutostartChanged))
            .collect();
        assert_eq!(
            logged,
            [
                (SessionEvent::Installed, None, None),
                (
                    SessionEvent::AutostartChanged,
                    Some("install".to_owned()),
                    None
                ),
            ]
        );
        let mut env = linux_env(1);
        let backends = Backends::default();
        let (done, _) = env.install(&[Some("y\n")], &backends);
        let err = done.unwrap_err().to_string();
        assert!(err.contains("re-authentication"), "{err}");
        assert!(env.files.installed(), "the install stays");
        assert_eq!(backends.installs(), 0);
        assert_eq!(env.dialogs.asked(), ["install", "service_install"]);
    }

    /// An install whose files fail after its line is logged again,
    /// `ok: false`; one whose dialog is refused writes nothing.
    #[test]
    fn a_failed_install_is_logged_and_a_refused_one_writes_nothing() {
        let mut env = linux_env(2);
        env.files.fail = Some("the disk is full");
        let (done, script) = env.install(&[], &Backends::default());
        assert_eq!(done.unwrap_err().to_string(), "the disk is full");
        assert!(!script.lines.iter().any(|l| l.starts_with("ask:")));
        let logged: Vec<_> = lines(&env)
            .into_iter()
            .filter(|(e, ..)| *e == SessionEvent::Installed)
            .collect();
        assert_eq!(
            logged,
            [
                (SessionEvent::Installed, None, None),
                (
                    SessionEvent::Installed,
                    Some("install failed".to_owned()),
                    Some(false)
                ),
            ]
        );
        let mut env = linux_env(0);
        let (done, _) = env.install(&[Some("y\n")], &Backends::default());
        assert!(done.unwrap_err().to_string().contains("re-authentication"));
        assert!(!env.files.installed());
        assert!(
            !lines(&env)
                .iter()
                .any(|(e, ..)| *e == SessionEvent::Installed)
        );
    }

    /// §B.1.1: beside a running Tornect host both commands are refused on
    /// both systems, before any dialog and before anything is read or
    /// written.
    #[test]
    fn install_and_uninstall_are_refused_while_a_host_runs() {
        let mut env = linux_env(2);
        let backends = Backends::default();
        let make = |spec| backends.make(spec);
        let mut script = Script::answering(&[]);
        let mut deps = Deps {
            ctx: &mut env.ctx,
            console: &mut script,
            host_running: true,
            autostart_for: &make,
        };
        let results = [
            install_linux(
                &mut deps,
                &env.paths,
                &env.files,
                &mut std::io::empty(),
                Err(NO_LYREBIRD_HERE.to_owned()),
            ),
            uninstall_linux(&mut deps, &env.paths, &env.files),
            install_windows(&mut deps, &env.paths, &Untouched, false),
            uninstall_windows(&mut deps, &env.paths, &Untouched),
        ];
        for done in results {
            assert_eq!(done.unwrap_err().to_string(), CLOSE_FIRST);
        }
        assert!(env.dialogs.asked().is_empty());
        assert!(backends.specs().is_empty());
        assert!(!env.files.installed());
        assert!(env.files.homes.lock().unwrap().is_empty());
    }

    /// §B.1.1 and decision M1-53 (10): on Windows `tornect install` refuses
    /// a custom home (the start-at-login task's rule), before anything is
    /// asked.
    #[test]
    fn install_refuses_a_custom_home_on_windows() {
        let mut env = env(windows_admin(), 2);
        let mut script = Script::answering(&[]);
        let backends = Backends::default();
        let make = |spec| backends.make(spec);
        let mut deps = Deps {
            ctx: &mut env.ctx,
            console: &mut script,
            host_running: false,
            autostart_for: &make,
        };
        let err = install_windows(&mut deps, &env.paths, &Untouched, true).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "{}; run `tornect install` without it",
                tornect_platform::autostart::WINDOWS_HOME_RULE
            )
        );
        assert!(env.dialogs.asked().is_empty());
        assert!(backends.specs().is_empty());
    }

    /// §B.1.1 (pairings and grants stay): uninstalling leaves the store's
    /// grants and the paired devices as they were, and says where they are.
    #[test]
    fn uninstall_keeps_pairings_and_grants() {
        let mut env = linux_env(4);
        assert!(
            unattended::dispatch(
                &env.ctx,
                IpcRequest {
                    id: 1,
                    op: IpcOp::On
                }
            )
            .ok
        );
        let device = DeviceId::from_bytes([7; 32]);
        env.ctx
            .guard
            .create_grant(
                Actor::Cli,
                &device,
                Preset::HeadlessBox,
                &GrantOptions::default(),
                &[0u8; 192],
                false,
            )
            .unwrap();
        std::fs::write(env.paths.trusted_devices_file(), b"# paired devices\n").unwrap();
        let grants = env.ctx.guard.store().grants();
        let backends = Backends::default();
        let (done, _) = env.install(&[Some("\n")], &backends);
        done.unwrap();
        let (done, script) = env.uninstall(&|spec| backends.make(spec));
        done.unwrap();
        // The store's flush time is kept to the second: a write in a later
        // second moves it.
        let unflushed = |mut grants: Vec<tornect_core::unattended::grant::UnattendedGrant>| {
            for grant in &mut grants {
                grant.fail.flushed_at = 0;
            }
            grants
        };
        assert_eq!(unflushed(env.ctx.guard.store().grants()), unflushed(grants));
        assert_eq!(
            std::fs::read(env.paths.trusted_devices_file()).unwrap(),
            b"# paired devices\n"
        );
        assert!(!env.files.installed());
        assert!(script.said(&format!(
            "Tornect is removed from this computer. Your pairings and grants stay in {}.",
            env.paths.state_dir.display()
        )));
        let ops: Vec<String> = env.dialogs.asked().into_iter().skip(1).collect();
        assert_eq!(ops, ["create_grant", "install", "uninstall"]);
    }

    /// `tornect uninstall` removes the start at sign-in whatever copy it
    /// runs (here an entry of another `tornect`, through the real autostart
    /// entry backend in the test's folder); with nothing left, a second
    /// uninstall asks nothing and says so.
    #[test]
    fn uninstall_removes_a_registration_of_any_copy() {
        let mut env = linux_env(2);
        let config = env.tmp.path().join("config");
        let entry = config.join("autostart").join("tornect.desktop");
        std::fs::create_dir_all(entry.parent().unwrap()).unwrap();
        std::fs::write(
            &entry,
            "[Desktop Entry]\nType=Application\nName=Tornect\nExec=\"/opt/other/tornect\" \"--background\"\n",
        )
        .unwrap();
        let real = |spec: LaunchSpec| -> Arc<dyn Autostart> {
            Arc::new(tornect_platform::autostart::XdgAutostart::for_config_home(
                &config,
                spec,
                Arc::new(tornect_platform::autostart::NoAutostart(
                    "no older unit here".to_owned(),
                )),
            ))
        };
        let (done, script) = env.uninstall(&real);
        done.unwrap();
        assert!(!entry.exists(), "the other copy's entry is still there");
        assert_eq!(env.dialogs.asked(), ["uninstall"]);
        assert!(script.said(&removed_line(&env.paths)));
        let (done, script) = env.uninstall(&real);
        done.unwrap();
        assert!(script.said(NOTHING_INSTALLED), "{:?}", script.lines);
        assert_eq!(env.dialogs.asked(), ["uninstall"], "a dialog for nothing");
    }

    /// §B.1.1 (pairings and grants stay; install moves no state): an install
    /// and its start at sign-in leave every file of the home as it was but
    /// `sessions.log` and the store's log head, and write nothing there.
    #[test]
    fn install_moves_no_state() {
        fn snapshot(root: &std::path::Path) -> Vec<(PathBuf, Vec<u8>)> {
            fn walk(dir: &std::path::Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
                for entry in std::fs::read_dir(dir).unwrap() {
                    let path = entry.unwrap().path();
                    if path.is_dir() {
                        walk(&path, out);
                    } else if !matches!(
                        path.file_name().and_then(|n| n.to_str()),
                        Some("sessions.log" | "unattended.bin")
                    ) {
                        out.push((path.clone(), std::fs::read(&path).unwrap()));
                    }
                }
            }
            let mut out = Vec::new();
            walk(root, &mut out);
            out.sort();
            out
        }
        let mut env = linux_env(2);
        let home = env.tmp.path().join("home");
        let before = snapshot(&home);
        let backends = Backends::default();
        let (done, _) = env.install(&[Some("y\n")], &backends);
        done.unwrap();
        assert_eq!(snapshot(&home), before);
        let bin: Vec<String> = std::fs::read_dir(&env.files.dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(bin, ["tornect"]);
    }

    /// §B.1.1 (the built default, which the operator kept): on Windows `tornect uninstall` is
    /// refused while a grant holds the administrator level, naming the
    /// device and `set-level <device> none`, and while the administrator
    /// helper task is registered; nothing is asked or removed.
    #[test]
    fn uninstall_is_refused_while_an_admin_grant_exists() {
        let mut env = env(windows_admin(), 4);
        assert!(
            unattended::dispatch(
                &env.ctx,
                IpcRequest {
                    id: 1,
                    op: IpcOp::On
                }
            )
            .ok
        );
        let device = DeviceId::from_bytes([9; 32]);
        env.ctx
            .guard
            .create_grant(
                Actor::Cli,
                &device,
                Preset::HeadlessBox,
                &GrantOptions {
                    elevation: Some(tornect_core::levels::Elevation::Admin),
                    ..GrantOptions::default()
                },
                &[0u8; 192],
                true,
            )
            .unwrap();
        let asked = env.dialogs.asked();
        let backends = Backends::default();
        let make = |spec| backends.make(spec);
        let mut script = Script::answering(&[]);
        let mut deps = Deps {
            ctx: &mut env.ctx,
            console: &mut script,
            host_running: false,
            autostart_for: &make,
        };
        let err = uninstall_windows(&mut deps, &env.paths, &Untouched)
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            format!(
                "{REMOVE_ADMIN_FIRST} ({} holds administrator access).",
                device.fingerprint()
            )
        );
        assert_eq!(env.dialogs.asked(), asked, "a dialog");
        assert!(backends.specs().is_empty());
        let mut env = self::env(
            FixedFacts::new(windows_admin_account(), HelperPresence::Registered),
            1,
        );
        let mut script = Script::answering(&[]);
        let mut deps = Deps {
            ctx: &mut env.ctx,
            console: &mut script,
            host_running: false,
            autostart_for: &make,
        };
        let err = uninstall_windows(&mut deps, &env.paths, &Untouched)
            .unwrap_err()
            .to_string();
        assert!(err.starts_with(REMOVE_ADMIN_FIRST), "{err}");
        assert!(err.contains("helper task is still registered"), "{err}");
        assert!(env.dialogs.asked().is_empty());
    }

    /// §B.1.1 (no install over an install, the operator's ruling): a start
    /// at sign-in that runs the installed copy, whose command cannot be read
    /// or whose status cannot be read, refuses `tornect install` before
    /// anything is asked; one that runs another copy does not.
    #[test]
    fn an_earlier_sign_in_start_refuses_the_install() {
        let installed = "C:\\Program Files\\Tornect\\tornect.exe";
        let registered = |command: Option<String>, unreadable: bool| {
            Some(AutostartState::Registered(Registration {
                enabled: true,
                elevated: false,
                command,
                note: None,
                unreadable,
            }))
        };
        let cases = [
            (
                "the installed copy",
                registered(
                    Some(format!("\"{}\" \"--background\"", installed.to_uppercase())),
                    false,
                ),
                false,
                true,
            ),
            (
                "a command that cannot be read",
                registered(None, true),
                false,
                true,
            ),
            ("a status that cannot be read", None, true, true),
            (
                "another copy",
                registered(
                    Some(
                        "\"C:\\Users\\u\\Downloads\\tornect\\tornect.exe\" \"--background\""
                            .to_owned(),
                    ),
                    false,
                ),
                false,
                false,
            ),
        ];
        for (what, state, unreadable, refused) in cases {
            let mut env = env(windows_admin(), 2);
            let backends = Backends {
                registered: state,
                unreadable,
                ..Backends::default()
            };
            let make = |spec| backends.make(spec);
            let mut script = Script::answering(&[]);
            let mut deps = Deps {
                ctx: &mut env.ctx,
                console: &mut script,
                host_running: false,
                autostart_for: &make,
            };
            let err = install_windows(&mut deps, &env.paths, &Bare, false)
                .unwrap_err()
                .to_string();
            if refused {
                assert_eq!(
                    err,
                    "Tornect is already installed in C:\\Program Files\\Tornect. Run tornect \
                     uninstall first.",
                    "{what}"
                );
            } else {
                assert_eq!(err, BARE_IMAGE, "{what}: it did not go on");
            }
            assert!(env.dialogs.asked().is_empty(), "{what}");
            assert_eq!(
                backends.specs(),
                [LaunchSpec {
                    exe: PathBuf::from(installed),
                    home: None,
                }],
                "{what}"
            );
            assert_eq!(backends.installs(), 0, "{what}");
        }
    }

    /// §B.1.1: on Windows `tornect uninstall` is refused while Tornect
    /// cannot read its grants (here a store file with no key, which fails
    /// closed), since it cannot tell whether a device still has
    /// administrator access; nothing is asked or removed.
    #[test]
    fn uninstall_is_refused_while_the_store_failed_closed() {
        let mut env = env_with(windows_admin(), 1, |paths| {
            std::fs::write(paths.unattended_store(), b"not a store").unwrap();
        });
        let status = env.ctx.guard.store().status();
        assert!(matches!(status, StoreStatus::FailedClosed(_)), "{status:?}");
        let backends = Backends::default();
        let make = |spec| backends.make(spec);
        let mut script = Script::answering(&[]);
        let mut deps = Deps {
            ctx: &mut env.ctx,
            console: &mut script,
            host_running: false,
            autostart_for: &make,
        };
        let err = uninstall_windows(&mut deps, &env.paths, &Untouched)
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "Tornect cannot read its grants now, so it cannot tell whether a device still has \
             administrator access; nothing was removed."
        );
        assert!(env.dialogs.asked().is_empty());
        assert!(backends.specs().is_empty());
    }

    /// Where unattended access was never enabled (no store, so no grant can
    /// exist) a Windows uninstall goes on to its steps: here it removes a
    /// start at sign-in after the guard's dialog.
    #[test]
    fn uninstall_goes_on_when_unattended_access_was_never_enabled() {
        let mut env = env(windows_admin(), 1);
        assert_eq!(env.ctx.guard.store().status(), StoreStatus::AttendedOnly);
        let backends = Backends {
            registered: Some(AutostartState::Registered(Registration {
                enabled: true,
                command: Some(
                    "\"C:\\Program Files\\Tornect\\tornect.exe\" \"--background\"".to_owned(),
                ),
                ..Registration::default()
            })),
            ..Backends::default()
        };
        let make = |spec| backends.make(spec);
        let mut script = Script::answering(&[]);
        let mut deps = Deps {
            ctx: &mut env.ctx,
            console: &mut script,
            host_running: false,
            autostart_for: &make,
        };
        uninstall_windows(&mut deps, &env.paths, &Bare).unwrap();
        assert_eq!(env.dialogs.asked(), ["uninstall"]);
        assert!(script.said(&removed_line(&env.paths)), "{:?}", script.lines);
        assert!(
            !script.lines.iter().any(|l| l.contains(GRANTS_UNREADABLE)),
            "{:?}",
            script.lines
        );
    }

    /// With nowhere to write (Windows: Apps and features starts the uninstall
    /// entry's command with no console), what the command says is kept, in
    /// order, for one message box, its error after the lines; nobody can answer
    /// a question there, so each is a no.
    #[test]
    fn with_nowhere_to_write_the_lines_and_the_error_go_into_one_message() {
        let mut collected = Collected::default();
        assert!(!collected.stdout_is_terminal());
        collected.out("first");
        assert_eq!(collected.ask(SIGN_IN_QUESTION), None);
        collected.err("second");
        assert_eq!(collected.text(&Ok(())), "first\nsecond");
        assert_eq!(
            collected.text(&Err(anyhow::anyhow!(CLOSE_FIRST))),
            format!("first\nsecond\n{CLOSE_FIRST}")
        );
        assert_eq!(
            Collected::default().text(&Err(anyhow::anyhow!(CLOSE_FIRST))),
            CLOSE_FIRST
        );
    }

    /// Owner Administrators; SYSTEM and Administrators full control, Users
    /// read and execute: what only administrators can change.
    fn admin_only_security() -> tornect_platform::helper_task::Security {
        use tornect_platform::helper_task::{Ace, Security};
        let ace = |sid: &str, mask| Ace {
            sid: sid.to_owned(),
            allow: true,
            mask,
            flags: 0,
        };
        Security {
            owner: "S-1-5-32-544".to_owned(),
            dacl: vec![
                ace("S-1-5-18", 0x001F_01FF),
                ace("S-1-5-32-544", 0x001F_01FF),
                ace("S-1-5-32-545", 0x0012_00A9),
            ],
        }
    }

    /// Windows with Tornect in Program Files (the folder administrators' only,
    /// no uninstall entry, no Start-menu entry), and this program the installed
    /// copy; every elevated step is recorded, and nothing can be read of this
    /// program once one ran. With `foreign_url`, another program's
    /// registration of `tornect:` links is there.
    #[derive(Default)]
    struct InstalledHere {
        ran: Mutex<Vec<Elevated>>,
        foreign_url: bool,
    }

    impl WindowsSystem for InstalledHere {
        fn program_files(&self) -> Result<String, InstallError> {
            Ok("C:\\Program Files".to_owned())
        }
        fn system_directory(&self) -> Result<String, InstallError> {
            Ok("C:\\Windows\\System32".to_owned())
        }
        fn start_menu_programs(&self) -> Result<String, InstallError> {
            Ok("C:\\Users\\u\\Start Menu\\Programs".to_owned())
        }
        fn open_own_image(&self) -> Result<Box<dyn HeldImage + '_>, InstallError> {
            panic!("opened the image")
        }
        fn folder_entries(&self, folder: &str) -> Result<Option<Vec<String>>, InstallError> {
            Ok((folder == "C:\\Program Files\\Tornect").then(|| vec!["tornect.exe".to_owned()]))
        }
        fn is_reparse_point(&self, _: &str) -> Result<bool, InstallError> {
            Ok(false)
        }
        fn read_file(&self, _: &str) -> Result<Box<dyn std::io::Read + '_>, InstallError> {
            panic!("read a file")
        }
        fn security(
            &self,
            _: &str,
        ) -> Result<tornect_platform::helper_task::Security, InstallError> {
            Ok(admin_only_security())
        }
        fn elevated_program(&self, step: &Elevated) -> String {
            let target = tornect_platform::install::WindowsTarget::of(self).unwrap();
            tornect_platform::install::elevated_command(step, &target).0
        }
        fn run_elevated(&self, step: &Elevated) -> Result<(), InstallError> {
            self.ran.lock().unwrap().push(step.clone());
            Ok(())
        }
        fn uninstall_entry_exists(&self, _: &str) -> Result<bool, InstallError> {
            Ok(false)
        }
        fn file_exists(&self, _: &str) -> Result<bool, InstallError> {
            Ok(false)
        }
        fn pending_removals(&self) -> Result<Vec<String>, InstallError> {
            panic!("read the list of removals")
        }
        fn own_path(&self) -> Result<String, InstallError> {
            if !self.ran.lock().unwrap().is_empty() {
                return Err(InstallError::Failed(
                    "this program read after its removal".to_owned(),
                ));
            }
            Ok("C:\\Program Files\\Tornect\\tornect.exe".to_owned())
        }
        fn write_shortcut(&self, _: &str, _: &str) -> Result<(), InstallError> {
            panic!("wrote a shortcut")
        }
        fn remove_shortcut(&self, _: &str) -> Result<(), InstallError> {
            panic!("removed a shortcut")
        }
        fn url_handler(&self) -> Result<UrlKey, InstallError> {
            Ok(if self.foreign_url {
                UrlKey::Other
            } else {
                UrlKey::Absent
            })
        }
        fn write_url_handler(&self, _: &str) -> Result<(), InstallError> {
            panic!("wrote the link registration")
        }
        fn remove_url_handler(&self) -> Result<(), InstallError> {
            panic!("removed the link registration")
        }
    }

    /// §B.1.1: an uninstall run from the installed copy (as Apps and features
    /// runs it) has that copy mark its folder for removal at the next restart,
    /// and says so before its last line; whether it runs from the installed
    /// copy is read before anything is removed, so nothing read after the
    /// removal can end a finished uninstall in an error. With nowhere to write,
    /// both lines go into the one message.
    #[test]
    fn an_uninstall_from_the_installed_copy_says_its_folder_goes_at_the_restart() {
        let mut env = env(windows_admin(), 1);
        let backends = Backends::default();
        let make = |spec| backends.make(spec);
        let sys = InstalledHere::default();
        let mut collected = Collected::default();
        let mut deps = Deps {
            ctx: &mut env.ctx,
            console: &mut collected,
            host_running: false,
            autostart_for: &make,
        };
        let done = uninstall_windows(&mut deps, &env.paths, &sys);
        assert!(done.is_ok(), "{done:?}");
        assert_eq!(
            *sys.ran.lock().unwrap(),
            [Elevated::RemoveAtRestart {
                folder: "C:\\Program Files\\Tornect".to_owned()
            }]
        );
        assert_eq!(env.dialogs.asked(), ["uninstall"]);
        assert_eq!(
            collected.text(&done),
            format!(
                "{}\n{}",
                at_the_restart_line("C:\\Program Files\\Tornect"),
                removed_line(&env.paths)
            )
        );
    }

    /// The program [`Fresh`] installs.
    const FRESH_PROGRAM: &[u8] = b"MZ the program";

    /// Where [`Fresh`]'s image is.
    const FRESH_IMAGE: &str = "C:\\Users\\u\\Downloads\\tornect.exe";

    /// The link registration's command for [`Fresh`]'s installed copy.
    const FRESH_URL_COMMAND: &str =
        "\"C:\\Program Files\\Tornect\\tornect.exe\" open-link -- \"%1\"";

    /// [`Fresh`]'s image, held.
    struct FreshImage(std::io::Cursor<&'static [u8]>);

    impl std::io::Read for FreshImage {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            std::io::Read::read(&mut self.0, buf)
        }
    }

    impl HeldImage for FreshImage {
        fn path(&self) -> &str {
            FRESH_IMAGE
        }
    }

    /// Windows with nothing of Tornect in Program Files, on which an install
    /// runs to its end (every step succeeds, and the copy is the held image),
    /// and this user's registration of `tornect:` links as `url` holds it.
    struct Fresh {
        url: Mutex<UrlKey>,
        copied: Mutex<bool>,
    }

    impl Fresh {
        fn with(url: UrlKey) -> Self {
            Self {
                url: Mutex::new(url),
                copied: Mutex::new(false),
            }
        }

        fn url(&self) -> UrlKey {
            self.url.lock().unwrap().clone()
        }
    }

    impl WindowsSystem for Fresh {
        fn program_files(&self) -> Result<String, InstallError> {
            Ok("C:\\Program Files".to_owned())
        }
        fn system_directory(&self) -> Result<String, InstallError> {
            Ok("C:\\Windows\\System32".to_owned())
        }
        fn start_menu_programs(&self) -> Result<String, InstallError> {
            Ok("C:\\Users\\u\\Start Menu\\Programs".to_owned())
        }
        fn open_own_image(&self) -> Result<Box<dyn HeldImage + '_>, InstallError> {
            Ok(Box::new(FreshImage(std::io::Cursor::new(FRESH_PROGRAM))))
        }
        fn folder_entries(&self, folder: &str) -> Result<Option<Vec<String>>, InstallError> {
            Ok(
                (*self.copied.lock().unwrap() && folder == "C:\\Program Files\\Tornect")
                    .then(|| vec!["tornect.exe".to_owned()]),
            )
        }
        fn is_reparse_point(&self, _: &str) -> Result<bool, InstallError> {
            Ok(false)
        }
        fn read_file(&self, _: &str) -> Result<Box<dyn std::io::Read + '_>, InstallError> {
            Ok(Box::new(std::io::Cursor::new(FRESH_PROGRAM)))
        }
        fn security(
            &self,
            _: &str,
        ) -> Result<tornect_platform::helper_task::Security, InstallError> {
            Ok(admin_only_security())
        }
        fn elevated_program(&self, step: &Elevated) -> String {
            let target = tornect_platform::install::WindowsTarget::of(self).unwrap();
            tornect_platform::install::elevated_command(step, &target).0
        }
        fn run_elevated(&self, step: &Elevated) -> Result<(), InstallError> {
            if matches!(step, Elevated::Copy { .. }) {
                *self.copied.lock().unwrap() = true;
            }
            Ok(())
        }
        fn uninstall_entry_exists(&self, _: &str) -> Result<bool, InstallError> {
            Ok(false)
        }
        fn file_exists(&self, _: &str) -> Result<bool, InstallError> {
            Ok(false)
        }
        fn pending_removals(&self) -> Result<Vec<String>, InstallError> {
            Ok(Vec::new())
        }
        fn own_path(&self) -> Result<String, InstallError> {
            Ok(FRESH_IMAGE.to_owned())
        }
        fn write_shortcut(&self, _: &str, _: &str) -> Result<(), InstallError> {
            Ok(())
        }
        fn remove_shortcut(&self, _: &str) -> Result<(), InstallError> {
            Ok(())
        }
        fn url_handler(&self) -> Result<UrlKey, InstallError> {
            Ok(self.url())
        }
        fn write_url_handler(&self, command: &str) -> Result<(), InstallError> {
            *self.url.lock().unwrap() = UrlKey::Command(command.to_owned());
            Ok(())
        }
        fn remove_url_handler(&self) -> Result<(), InstallError> {
            *self.url.lock().unwrap() = UrlKey::Absent;
            Ok(())
        }
    }

    /// Design `invite` §4.6: a Windows install's line says, word for word,
    /// what `tornect:` links open: Tornect where the install wrote the
    /// registration or found its own leftover, another program where another
    /// registration is there, which stays as it was.
    #[test]
    fn the_windows_install_says_what_links_do() {
        let registered =
            "Tornect is installed in C:\\Program Files\\Tornect; tornect:// links open it.";
        let other = "Tornect is installed in C:\\Program Files\\Tornect. tornect:// links open \
                     another program here (HKEY_CURRENT_USER\\Software\\Classes\\tornect); Tornect \
                     left that as it is.";
        let folder = "C:\\Program Files\\Tornect";
        assert_eq!(
            windows_installed(folder, WindowsLinks::Registered),
            registered
        );
        assert_eq!(windows_installed(folder, WindowsLinks::OtherProgram), other);
        let ours = UrlKey::Command(FRESH_URL_COMMAND.to_owned());
        let theirs = UrlKey::Command("\"C:\\Program Files\\Other\\other.exe\" \"%1\"".to_owned());
        for (found, line, after) in [
            (UrlKey::Absent, registered, ours.clone()),
            (ours.clone(), registered, ours.clone()),
            (theirs.clone(), other, theirs.clone()),
            (UrlKey::Other, other, UrlKey::Other),
        ] {
            let mut env = env(windows_admin(), 1);
            let backends = Backends::default();
            let make = |spec| backends.make(spec);
            let sys = Fresh::with(found.clone());
            let mut script = Script::answering(&[]);
            let mut deps = Deps {
                ctx: &mut env.ctx,
                console: &mut script,
                host_running: false,
                autostart_for: &make,
            };
            install_windows(&mut deps, &env.paths, &sys, false).unwrap();
            assert!(script.said(line), "{found:?}: {:?}", script.lines);
            // The final audit before the release: the Program Files copy
            // carries no lyrebird yet (decision M1-88), and says so.
            assert!(script.said(WINDOWS_NO_BRIDGES), "{:?}", script.lines);
            assert!(
                !script
                    .lines
                    .iter()
                    .any(|l| l.contains("tornect://") && l != &format!("out: {line}")),
                "{found:?}: {:?}",
                script.lines
            );
            assert_eq!(sys.url(), after, "{found:?}");
            assert_eq!(env.dialogs.asked(), ["install"], "{found:?}");
        }
    }

    /// Design `invite` §4.6: a Windows uninstall that left another program's
    /// registration of `tornect:` links says so before its other lines, also
    /// where nothing else of Tornect was there (nothing is asked then); one
    /// that removed Tornect's own registration says nothing of links.
    #[test]
    fn the_windows_uninstall_names_a_link_registration_it_left() {
        let left = "tornect:// links open another program here \
                    (HKEY_CURRENT_USER\\Software\\Classes\\tornect); Tornect left that as it is.";
        assert_eq!(url_handler_left_line(), left);

        let mut env = env(windows_admin(), 1);
        let backends = Backends::default();
        let make = |spec| backends.make(spec);
        let sys = InstalledHere {
            foreign_url: true,
            ..InstalledHere::default()
        };
        let mut collected = Collected::default();
        let mut deps = Deps {
            ctx: &mut env.ctx,
            console: &mut collected,
            host_running: false,
            autostart_for: &make,
        };
        let done = uninstall_windows(&mut deps, &env.paths, &sys);
        assert!(done.is_ok(), "{done:?}");
        assert_eq!(
            collected.text(&done),
            format!(
                "{left}\n{}\n{}",
                at_the_restart_line("C:\\Program Files\\Tornect"),
                removed_line(&env.paths)
            )
        );

        let mut env = self::env(windows_admin(), 1);
        let sys = Fresh::with(UrlKey::Other);
        let mut collected = Collected::default();
        let mut deps = Deps {
            ctx: &mut env.ctx,
            console: &mut collected,
            host_running: false,
            autostart_for: &make,
        };
        let done = uninstall_windows(&mut deps, &env.paths, &sys);
        assert_eq!(
            collected.text(&done),
            format!("{left}\n{NOTHING_INSTALLED}")
        );
        assert!(env.dialogs.asked().is_empty());
        assert_eq!(sys.url(), UrlKey::Other);

        // Nothing in Program Files, but a start at sign-in of some copy.
        let mut env = self::env(windows_admin(), 1);
        let signed_in = Backends {
            registered: Some(AutostartState::Registered(Registration {
                enabled: true,
                command: Some("\"C:\\Users\\u\\tornect.exe\" \"--background\"".to_owned()),
                ..Registration::default()
            })),
            ..Backends::default()
        };
        let make_signed_in = |spec| signed_in.make(spec);
        let mut collected = Collected::default();
        let mut deps = Deps {
            ctx: &mut env.ctx,
            console: &mut collected,
            host_running: false,
            autostart_for: &make_signed_in,
        };
        let done = uninstall_windows(&mut deps, &env.paths, &sys);
        assert_eq!(
            collected.text(&done),
            format!("{left}\n{}", removed_line(&env.paths))
        );
        assert_eq!(env.dialogs.asked(), ["uninstall"]);
        assert_eq!(sys.url(), UrlKey::Other);

        // Tornect's own registration, left alone: removed after the dialog.
        let mut env = self::env(windows_admin(), 1);
        let sys = Fresh::with(UrlKey::Command(FRESH_URL_COMMAND.to_owned()));
        let mut collected = Collected::default();
        let mut deps = Deps {
            ctx: &mut env.ctx,
            console: &mut collected,
            host_running: false,
            autostart_for: &make,
        };
        let done = uninstall_windows(&mut deps, &env.paths, &sys);
        assert_eq!(collected.text(&done), removed_line(&env.paths));
        assert_eq!(env.dialogs.asked(), ["uninstall"]);
        assert_eq!(sys.url(), UrlKey::Absent);
    }
}
