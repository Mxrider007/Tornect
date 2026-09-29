//! The on-demand administrator helper task (`docs/PLAN.md` §B.8.7.5; r7,
//! M-FEAT-3): `\Tornect admin helper <SID>`, which starts `tornect
//! input-helper` elevated for an unattended session of an admin grant.
//!
//! Principal this user (by SID), `HighestAvailable`, **no trigger**,
//! `AllowStartOnDemand` true (for this task only; the start-at-login task
//! keeps F1-5's false), one action: the executable's absolute path under
//! `FOLDERID_ProgramFiles` — never a `%` variable, which the Task Scheduler
//! expands with no escape (F1-4) — with the arguments `input-helper
//! $(Arg0)`, the run parameter being the helper's command line (the pipe,
//! the host's id, the time limit).
//!
//! MUSTs kept here, each decided by a pure function tested on every system
//! over a fake scheduler: registered only while an active admin grant exists
//! and disabled while unattended access is off (H7, [`want`]); registered
//! only from Program Files, read back and compared (principal, run level,
//! command, arguments, exactly one action; H6, F1-2, [`register`]); the
//! install folder and the executable carry no write, delete or owner-change
//! entry for anyone but SYSTEM, Administrators and TrustedInstaller, checked
//! at registration and before each run, a failed check refusing (H6,
//! [`admin_only`]). The Windows scheduler calls are NEEDS-DEVICE(windows);
//! `IRegisteredTask::Run` with the run parameter is UNVERIFIED on a device.
//!
//! What this cannot keep out (§B.8.7.5 *Residual*): whatever lets the host
//! run the task lets every program of this user run it.

use crate::autostart::{AutostartError, location_under, task_command, task_facts};

/// The task's name for the user `sid` (a per-user name).
#[must_use]
pub fn task_name(sid: &str) -> String {
    format!("Tornect admin helper {sid}")
}

/// The action's arguments: the helper's command line comes as the run
/// parameter `$(Arg0)`.
pub const ARGUMENTS: &str = "input-helper $(Arg0)";

/// The longest the task lets a helper run (§B.8.7.5: 12 h).
pub const TIME_LIMIT: &str = "PT12H";

/// The task definition for `exe` under `program_files`, run as `sid`.
/// Refused: an executable outside Program Files, a `%` in its path, a SID
/// that is not one.
pub fn xml(exe: &str, program_files: &str, sid: &str) -> Result<String, AutostartError> {
    if !location_under(exe, &[program_files.to_owned()]) {
        return Err(AutostartError::Unavailable(format!(
            "the administrator helper runs only from Program Files ({program_files}), and this \
             Tornect is at {exe}"
        )));
    }
    let command = escape(&task_command(exe)?);
    if !sid.starts_with("S-1-")
        || !sid
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'-' || b == b'S')
    {
        return Err(AutostartError::Unquotable(format!("not a SID: {sid}")));
    }
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n\
<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n\
  <RegistrationInfo>\r\n\
    <Description>Tornect: the administrator helper of an unattended administrator session. Registered with the first administrator grant, removed with the last.</Description>\r\n\
  </RegistrationInfo>\r\n\
  <Triggers />\r\n\
  <Principals>\r\n\
    <Principal id=\"Author\">\r\n\
      <UserId>{sid}</UserId>\r\n\
      <LogonType>InteractiveToken</LogonType>\r\n\
      <RunLevel>HighestAvailable</RunLevel>\r\n\
    </Principal>\r\n\
  </Principals>\r\n\
  <Settings>\r\n\
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\r\n\
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\r\n\
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\r\n\
    <AllowHardTerminate>true</AllowHardTerminate>\r\n\
    <StartWhenAvailable>false</StartWhenAvailable>\r\n\
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\r\n\
    <AllowStartOnDemand>true</AllowStartOnDemand>\r\n\
    <Enabled>true</Enabled>\r\n\
    <Hidden>false</Hidden>\r\n\
    <RunOnlyIfIdle>false</RunOnlyIfIdle>\r\n\
    <WakeToRun>false</WakeToRun>\r\n\
    <ExecutionTimeLimit>{TIME_LIMIT}</ExecutionTimeLimit>\r\n\
    <Priority>5</Priority>\r\n\
  </Settings>\r\n\
  <Actions Context=\"Author\">\r\n\
    <Exec>\r\n\
      <Command>{command}</Command>\r\n\
      <Arguments>{ARGUMENTS}</Arguments>\r\n\
    </Exec>\r\n\
  </Actions>\r\n\
</Task>\r\n"
    ))
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Whether the registered definition is the one written (F1-2): only
/// elements, exactly one action, this account, `HighestAvailable`, the same
/// command and arguments, no trigger, and on-demand starts allowed.
pub fn matches(
    written: &str,
    registered: &str,
    is_this_account: &dyn Fn(&str) -> bool,
) -> Result<(), String> {
    crate::autostart::registered_matches(
        &task_facts(written),
        &task_facts(registered),
        is_this_account,
    )?;
    // Every trigger element's name ends in "Trigger"; the one "Triggers"
    // container does not count.
    if registered.matches("Trigger").count() > registered.matches("Triggers").count() {
        return Err("the task has a trigger".to_owned());
    }
    Ok(())
}

/// Whether the helper task should exist, and enabled (H7; §B.8.7.5 task
/// lifetime).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Want {
    /// No active admin grant: the task must not exist.
    Absent,
    /// An active admin grant while unattended access is on.
    Enabled,
    /// An active admin grant, unattended access off: registered, disabled.
    Disabled,
}

/// What the task should be, from the number of active admin grants and the
/// master switch.
#[must_use]
pub fn want(active_admin_grants: usize, master_on: bool) -> Want {
    match (active_admin_grants, master_on) {
        (0, _) => Want::Absent,
        (_, true) => Want::Enabled,
        (_, false) => Want::Disabled,
    }
}

/// One entry of a file's or folder's DACL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ace {
    /// The trustee, as a string SID.
    pub sid: String,
    /// An allow entry (a deny entry takes nothing away from this check).
    pub allow: bool,
    /// The access mask.
    pub mask: u32,
}

/// Rights that let a principal change or replace the executable or what its
/// folder holds: write data, append, write extended attributes or
/// attributes, delete a child, delete, change the DACL, take ownership, and
/// the generic write and all rights.
pub const WRITE_RIGHTS: u32 = 0x0000_0002
    | 0x0000_0004
    | 0x0000_0010
    | 0x0000_0040
    | 0x0000_0100
    | 0x0001_0000
    | 0x0004_0000
    | 0x0008_0000
    | 0x1000_0000
    | 0x4000_0000;

/// The principals that may hold [`WRITE_RIGHTS`]: SYSTEM, Administrators,
/// TrustedInstaller.
pub const TRUSTED: [&str; 3] = [
    "S-1-5-18",
    "S-1-5-32-544",
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
];

/// The ACL check of H6: no allow entry gives [`WRITE_RIGHTS`] to anyone but
/// [`TRUSTED`]. `what` names the file or folder in the refusal.
pub fn admin_only(what: &str, dacl: &[Ace]) -> Result<(), String> {
    for ace in dacl {
        if ace.allow && ace.mask & WRITE_RIGHTS != 0 && !TRUSTED.contains(&ace.sid.as_str()) {
            return Err(format!(
                "{what} can be changed by {} (rights {:#x}), not only by administrators",
                ace.sid, ace.mask
            ));
        }
    }
    Ok(())
}

/// The Task Scheduler and the file system as the helper task needs them;
/// a fake in tests.
pub trait HelperTasks {
    /// The registered definition, `None` when there is no task.
    fn query(&self) -> Result<Option<String>, AutostartError>;
    /// Register `xml` (elevated: through the UAC prompt when needed).
    fn register(&self, xml: &str) -> Result<(), AutostartError>;
    /// Delete the task (elevated when needed).
    fn delete(&self) -> Result<(), AutostartError>;
    /// Enable or disable it.
    fn set_enabled(&self, enabled: bool) -> Result<(), AutostartError>;
    /// The DACL of `path` (a file or folder).
    fn dacl(&self, path: &str) -> Result<Vec<Ace>, AutostartError>;
    /// Start it with the run parameter `arg` (`IRegisteredTask::Run`).
    fn run(&self, arg: &str) -> Result<(), AutostartError>;
    /// Whether `principal` (a SID or a name) is this account.
    fn is_this_account(&self, principal: &str) -> bool;
}

/// Where the helper runs from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Install {
    /// The executable, absolute, under Program Files.
    pub exe: String,
    /// Its folder.
    pub folder: String,
    /// `FOLDERID_ProgramFiles`.
    pub program_files: String,
    /// This user's SID.
    pub sid: String,
}

/// H6's ACL check of the folder and the executable.
pub fn check_files(ts: &dyn HelperTasks, install: &Install) -> Result<(), AutostartError> {
    for path in [&install.folder, &install.exe] {
        admin_only(path, &ts.dacl(path)?).map_err(AutostartError::Unavailable)?;
    }
    Ok(())
}

/// Register the task (H6): the ACL check, the registration, then the read
/// back; a registration that differs is removed and refused.
pub fn register(ts: &dyn HelperTasks, install: &Install) -> Result<(), AutostartError> {
    let written = xml(&install.exe, &install.program_files, &install.sid)?;
    check_files(ts, install)?;
    ts.register(&written)?;
    let registered = ts.query()?.ok_or_else(|| {
        AutostartError::Failed(
            "the administrator helper task is not there after registering".into(),
        )
    })?;
    if let Err(what) = matches(&written, &registered, &|p| ts.is_this_account(p)) {
        let removed = ts.delete();
        return Err(AutostartError::Failed(format!(
            "the administrator helper task registered is not the one Tornect wrote ({what}); {}",
            if removed.is_ok() {
                "it was removed".to_owned()
            } else {
                format!(
                    "removing it failed: {}",
                    crate::autostart::MANUAL_TASK_DELETE
                )
            }
        )));
    }
    Ok(())
}

/// Bring the task to `want` (the task lifetime, H7): remove it when no
/// active admin grant exists, register it (with every check) when one does,
/// and enable or disable it with the master switch.
pub fn sync(ts: &dyn HelperTasks, install: &Install, want: Want) -> Result<(), AutostartError> {
    let present = ts.query()?.is_some();
    match want {
        Want::Absent => {
            if present {
                ts.delete()?;
            }
            Ok(())
        }
        Want::Enabled | Want::Disabled => {
            if !present {
                register(ts, install)?;
            }
            ts.set_enabled(want == Want::Enabled)
        }
    }
}

/// Start the helper through the task for one session: the ACL check again
/// (H6, before each run), then `Run` with the helper's command line.
pub fn run(
    ts: &dyn HelperTasks,
    install: &Install,
    args: &crate::helper::HelperArgs,
) -> Result<(), AutostartError> {
    check_files(ts, install)?;
    ts.run(&args.to_args().join(" "))
}

/// The readiness line "administrator helper registered" (§B.8.14): whether
/// the task exists, as the scheduler reports it.
#[must_use]
pub fn readiness(present: &Result<Option<String>, AutostartError>) -> String {
    match present {
        Ok(Some(_)) => "administrator helper registered".to_owned(),
        Ok(None) => "administrator helper not registered (no administrator grant)".to_owned(),
        Err(e) => format!("could not read the administrator helper task: {e}"),
    }
}

/// This user's helper task on Windows: `schtasks.exe` from the system
/// directory (changes through the UAC prompt), the DACL reads, and the
/// on-demand run through the Task Scheduler's COM API. NEEDS-DEVICE(windows).
#[cfg(windows)]
pub fn for_this_user() -> Result<impl HelperTasks, AutostartError> {
    crate::win_task::scheduler()
}

/// Where this installed Tornect's helper runs from: its image as Windows
/// reports it, its folder, `FOLDERID_ProgramFiles` and this user's SID.
#[cfg(windows)]
pub fn this_install() -> Result<Install, AutostartError> {
    let failed = |what: &str, e: std::io::Error| AutostartError::Failed(format!("{what}: {e}"));
    let exe = crate::helper::own_image().map_err(|e| failed("reading this program's path", e))?;
    let folder = std::path::Path::new(&exe)
        .parent()
        .and_then(|p| p.to_str())
        .ok_or_else(|| AutostartError::Failed("this program has no folder".to_owned()))?
        .to_owned();
    let program_files = crate::win::known_folder(crate::win::KnownFolder::ProgramFiles)
        .map_err(|e| failed("finding Program Files", e))?
        .to_str()
        .ok_or_else(|| AutostartError::Failed("Program Files is not Unicode".to_owned()))?
        .to_owned();
    let sid = crate::win::current_user_sid().map_err(|e| failed("reading this user's SID", e))?;
    Ok(Install {
        exe,
        folder,
        program_files,
        sid,
    })
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    const SID: &str = "S-1-5-21-1-2-3-1001";
    const PF: &str = r"C:\Program Files";

    fn install() -> Install {
        Install {
            exe: r"C:\Program Files\Tornect\tornect.exe".to_owned(),
            folder: r"C:\Program Files\Tornect".to_owned(),
            program_files: PF.to_owned(),
            sid: SID.to_owned(),
        }
    }

    fn admin_acl() -> Vec<Ace> {
        vec![
            Ace {
                sid: TRUSTED[0].to_owned(),
                allow: true,
                mask: 0x1F_01FF,
            },
            Ace {
                sid: TRUSTED[1].to_owned(),
                allow: true,
                mask: 0x1F_01FF,
            },
            // Users: read and execute.
            Ace {
                sid: "S-1-5-32-545".to_owned(),
                allow: true,
                mask: 0x0012_00A9,
            },
        ]
    }

    /// A scheduler with at most one task; every call recorded.
    #[derive(Default)]
    struct Fake {
        task: RefCell<Option<String>>,
        enabled: RefCell<bool>,
        acl: RefCell<Vec<Ace>>,
        /// What the scheduler stores instead of what was written.
        tamper: Option<fn(&str) -> String>,
        calls: RefCell<Vec<String>>,
    }

    impl Fake {
        fn new() -> Self {
            Self {
                acl: RefCell::new(admin_acl()),
                ..Self::default()
            }
        }
        fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }
    }

    impl HelperTasks for Fake {
        fn query(&self) -> Result<Option<String>, AutostartError> {
            Ok(self.task.borrow().clone())
        }
        fn register(&self, xml: &str) -> Result<(), AutostartError> {
            self.calls.borrow_mut().push("register".into());
            *self.task.borrow_mut() = Some(self.tamper.map_or_else(|| xml.to_owned(), |t| t(xml)));
            *self.enabled.borrow_mut() = true;
            Ok(())
        }
        fn delete(&self) -> Result<(), AutostartError> {
            self.calls.borrow_mut().push("delete".into());
            *self.task.borrow_mut() = None;
            Ok(())
        }
        fn set_enabled(&self, enabled: bool) -> Result<(), AutostartError> {
            self.calls.borrow_mut().push(format!("enabled {enabled}"));
            *self.enabled.borrow_mut() = enabled;
            Ok(())
        }
        fn dacl(&self, _: &str) -> Result<Vec<Ace>, AutostartError> {
            Ok(self.acl.borrow().clone())
        }
        fn run(&self, arg: &str) -> Result<(), AutostartError> {
            self.calls.borrow_mut().push(format!("run {arg}"));
            Ok(())
        }
        fn is_this_account(&self, principal: &str) -> bool {
            principal == SID
        }
    }

    /// H7: registered with the first active admin grant, removed with the
    /// last, disabled while unattended access is off.
    #[test]
    fn the_task_lives_exactly_while_an_admin_grant_does() {
        assert_eq!(want(0, true), Want::Absent);
        assert_eq!(want(0, false), Want::Absent);
        assert_eq!(want(1, true), Want::Enabled);
        assert_eq!(want(3, false), Want::Disabled);
        let ts = Fake::new();
        sync(&ts, &install(), want(0, true)).unwrap();
        assert!(ts.task.borrow().is_none(), "never without a grant");
        assert!(ts.calls().is_empty());
        sync(&ts, &install(), want(1, true)).unwrap();
        assert!(ts.task.borrow().is_some() && *ts.enabled.borrow());
        sync(&ts, &install(), want(1, false)).unwrap();
        assert!(
            ts.task.borrow().is_some() && !*ts.enabled.borrow(),
            "disabled"
        );
        sync(&ts, &install(), want(0, false)).unwrap();
        assert!(ts.task.borrow().is_none(), "gone with the last grant");
        assert_eq!(
            ts.calls(),
            ["register", "enabled true", "enabled false", "delete"]
        );
    }

    /// H6: the definition — this user, `HighestAvailable`, no trigger, on
    /// demand, one action from Program Files — read back and compared; a
    /// registration that differs is removed.
    #[test]
    fn the_registration_is_read_back_and_a_different_one_removed() {
        let written = xml(&install().exe, PF, SID).unwrap();
        for part in [
            "<RunLevel>HighestAvailable</RunLevel>",
            "<Triggers />",
            "<AllowStartOnDemand>true</AllowStartOnDemand>",
            "<Arguments>input-helper $(Arg0)</Arguments>",
            &format!("<UserId>{SID}</UserId>"),
            "<ExecutionTimeLimit>PT12H</ExecutionTimeLimit>",
        ] {
            assert!(written.contains(part), "{part}");
        }
        let ts = Fake::new();
        register(&ts, &install()).unwrap();
        for tamper in [
            (|x: &str| x.replace("tornect.exe", "evil.exe")) as fn(&str) -> String,
            |x: &str| x.replace("HighestAvailable", "LeastPrivilege"),
            |x: &str| x.replace(SID, "S-1-5-18"),
            |x: &str| x.replace("input-helper $(Arg0)", "input-helper $(Arg0) --x"),
            |x: &str| {
                x.replace(
                    "</Exec>",
                    "</Exec><Exec><Command>C:\\x.exe</Command></Exec>",
                )
            },
            |x: &str| x.replace("<Triggers />", "<Triggers><BootTrigger /></Triggers>"),
        ] {
            let ts = Fake {
                tamper: Some(tamper),
                ..Fake::new()
            };
            assert!(register(&ts, &install()).is_err());
            assert!(ts.task.borrow().is_none(), "removed");
            assert_eq!(ts.calls(), ["register", "delete"]);
        }
    }

    /// H6: never a `%` path (F1-4), never outside Program Files.
    #[test]
    fn a_percent_path_or_one_outside_program_files_is_refused() {
        for exe in [
            r"%ProgramFiles%\Tornect\tornect.exe",
            r"C:\Program Files\%X%\tornect.exe",
            r"C:\Users\a\tornect.exe",
            r"C:\Program FilesX\tornect.exe",
        ] {
            assert!(xml(exe, PF, SID).is_err(), "{exe}");
            let ts = Fake::new();
            let at = Install {
                exe: exe.to_owned(),
                ..install()
            };
            assert!(register(&ts, &at).is_err(), "{exe}");
            assert!(ts.calls().is_empty(), "nothing registered: {exe}");
        }
        assert!(xml(&install().exe, PF, "not-a-sid").is_err());
    }

    /// H6: a write, delete or owner-change entry for anyone but SYSTEM,
    /// Administrators or TrustedInstaller refuses the registration and every
    /// run; read and execute for Users is fine.
    #[test]
    fn a_folder_others_can_change_refuses_registration_and_run() {
        let args = crate::helper::HelperArgs {
            pipe: crate::helper::pipe_name(&[9; 16]),
            host_pid: 88,
            hard_cap: std::time::Duration::from_secs(3600),
        };
        let ts = Fake::new();
        register(&ts, &install()).unwrap();
        run(&ts, &install(), &args).unwrap();
        assert_eq!(
            ts.calls().last().unwrap(),
            &format!("run {} 88 3600", args.pipe)
        );
        for mask in [
            0x2,
            0x4,
            0x10,
            0x40,
            0x100,
            0x1_0000,
            0x4_0000,
            0x8_0000,
            0x1000_0000,
            0x4000_0000,
        ] {
            let ts = Fake::new();
            ts.acl.borrow_mut().push(Ace {
                sid: "S-1-5-11".to_owned(),
                allow: true,
                mask,
            });
            assert!(register(&ts, &install()).is_err(), "{mask:#x}");
            assert!(run(&ts, &install(), &args).is_err(), "{mask:#x}");
            assert!(ts.calls().is_empty(), "{mask:#x}");
        }
        let deny = [Ace {
            sid: "S-1-5-11".to_owned(),
            allow: false,
            mask: 0x4000_0000,
        }];
        assert!(
            admin_only("f", &deny).is_ok(),
            "a deny entry grants nothing"
        );
    }

    #[test]
    fn the_readiness_line_says_whether_it_is_registered() {
        assert_eq!(
            readiness(&Ok(Some(String::new()))),
            "administrator helper registered"
        );
        assert!(readiness(&Ok(None)).contains("not registered"));
        assert!(readiness(&Err(AutostartError::Failed("x".into()))).contains("could not read"));
        assert_eq!(task_name(SID), format!("Tornect admin helper {SID}"));
    }
}
