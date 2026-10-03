//! Installing Tornect (`docs/PLAN.md` §B.1.1, r7): the file work of
//! `tornect install` and `tornect uninstall`. The command runs it only after
//! the mutation guard's operation (access-increasing, §B.8.6.2: a fresh OS
//! re-authentication, no remote session for 60 s, logged); this module
//! performs the effect and nothing else.
//!
//! **Linux** ([`LinuxInstall`]): a per-user install without root. The
//! executable is copied to `~/.local/bin/tornect` and a menu entry is written
//! to `~/.local/share/applications/tornect.desktop`, with the keys `Type`,
//! `Name` and `Exec` only, `Exec` quoted by
//! [`desktop_exec`](crate::autostart::desktop_exec), the function the
//! start-at-sign-in entry uses. Before anything is written, the folder of the
//! executable passes the start at login's location rule
//! ([`unix_exe_location_ok`](crate::autostart::unix_exe_location_ok): neither
//! it nor a folder above it can be changed by another account, and none is a
//! link). Each file is written to a new temporary file in its folder and
//! renamed over its name, so a link found at either name is replaced, never
//! followed. Uninstalling removes exactly these two files, and only where they
//! are regular files.
//!
//! The folders come from the caller ([`LinuxInstall::new`]) or from `HOME`
//! ([`LinuxInstall::for_this_user`]), never from Tornect's data directory or
//! `--home`, which hold state, not programs. What starts at sign-in is not
//! this module's: the command registers it through the start-at-login
//! backend, and removes it the same way.

/// The name the installed program's menu entry shows.
pub const ENTRY_NAME: &str = "Tornect";

/// Why an install or an uninstall did not happen, or did not finish.
#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    /// Not possible in this build or on this computer; nothing was changed.
    #[error("{0}")]
    Unavailable(String),
    /// A check refused it: nothing was written, or what was written was
    /// undone, as the message says.
    #[error("{0}")]
    Refused(String),
    /// A file could not be written, read or removed.
    #[error("{0}")]
    Failed(String),
}

#[cfg(target_os = "linux")]
pub use linux::{FOLDER_OTHERS_CAN_CHANGE, LINUX_EXE, LinuxInstall, MENU_ENTRY, Removal};

/// The per-user install on Linux.
#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::OsString;
    use std::io::{ErrorKind, Write as _};
    use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};

    use super::{ENTRY_NAME, InstallError};
    use crate::autostart::{
        AutostartError, PathFacts, desktop_exec, parse_status_ids, unix_exe_location_ok,
    };

    /// The installed executable's name in the bin folder.
    pub const LINUX_EXE: &str = "tornect";

    /// The menu entry's file name in the applications folder.
    pub const MENU_ENTRY: &str = "tornect.desktop";

    /// Why the bin folder cannot take the copy: it, or a folder above it,
    /// fails the location rule; the rule's own reason follows.
    pub const FOLDER_OTHERS_CAN_CHANGE: &str =
        "This folder can be changed by other accounts, so Tornect cannot start from it.";

    /// What the location rule reads of the file system: this user's ids and a
    /// `stat` that does not follow links.
    #[derive(Clone, Copy)]
    struct Facts {
        uid: u32,
        gid: u32,
        stat: fn(&Path) -> std::io::Result<PathFacts>,
    }

    /// `stat` without following a link, as the location rule needs it.
    fn real_stat(path: &Path) -> std::io::Result<PathFacts> {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::symlink_metadata(path).map(|m| PathFacts {
            uid: m.uid(),
            gid: m.gid(),
            mode: m.mode(),
            symlink: m.file_type().is_symlink(),
        })
    }

    /// The per-user install: the executable in `bin_dir`, the menu entry in
    /// `apps_dir`.
    #[derive(Clone)]
    pub struct LinuxInstall {
        bin_dir: PathBuf,
        apps_dir: PathBuf,
        /// The tests' file facts; elsewhere this process's, always.
        #[cfg(test)]
        facts: Option<Facts>,
    }

    impl std::fmt::Debug for LinuxInstall {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("LinuxInstall")
                .field("bin_dir", &self.bin_dir)
                .field("apps_dir", &self.apps_dir)
                .finish_non_exhaustive()
        }
    }

    /// What [`LinuxInstall::uninstall`] did.
    #[derive(Debug, Default, Clone, PartialEq, Eq)]
    pub struct Removal {
        /// Removed, in this order.
        pub removed: Vec<PathBuf>,
        /// Found at an install's name but not a regular file (a link, a
        /// folder): not what `install` wrote, so left as it is.
        pub left: Vec<PathBuf>,
    }

    impl LinuxInstall {
        /// The install into `bin_dir` (the executable) and `apps_dir` (the
        /// menu entry), both absolute.
        #[must_use]
        pub fn new(bin_dir: PathBuf, apps_dir: PathBuf) -> Self {
            Self {
                bin_dir,
                apps_dir,
                #[cfg(test)]
                facts: None,
            }
        }

        /// This user's install (§B.1.1): `$HOME/.local/bin` and
        /// `$HOME/.local/share/applications`.
        pub fn for_this_user() -> Result<Self, InstallError> {
            let home = std::env::var_os("HOME")
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .ok_or_else(|| {
                    InstallError::Unavailable(
                        "HOME does not name this user's home folder, so Tornect does not know \
                         where to install"
                            .to_owned(),
                    )
                })?;
            Ok(Self::new(
                home.join(".local").join("bin"),
                home.join(".local").join("share").join("applications"),
            ))
        }

        /// The same install with the tests' file facts (the location rule
        /// itself still runs).
        #[cfg(test)]
        fn with_facts(
            mut self,
            uid: u32,
            gid: u32,
            stat: fn(&Path) -> std::io::Result<PathFacts>,
        ) -> Self {
            self.facts = Some(Facts { uid, gid, stat });
            self
        }

        /// The installed executable.
        #[must_use]
        pub fn exe(&self) -> PathBuf {
            self.bin_dir.join(LINUX_EXE)
        }

        /// The menu entry.
        #[must_use]
        pub fn menu_entry(&self) -> PathBuf {
            self.apps_dir.join(MENU_ENTRY)
        }

        /// The menu entry's text: the keys `Type`, `Name` and `Exec` only,
        /// `Exec` opening the installed window, with `--home` when the
        /// install is for a custom home (absolute).
        pub fn menu_entry_text(&self, home: Option<&Path>) -> Result<String, InstallError> {
            let mut args = Vec::new();
            if let Some(home) = home {
                if !home.is_absolute() {
                    return Err(InstallError::Unavailable(format!(
                        "the home {} is not an absolute path",
                        home.display()
                    )));
                }
                args.push(OsString::from("--home"));
                args.push(home.as_os_str().to_owned());
            }
            let exec = desktop_exec(&self.exe(), &args)
                .map_err(|e| InstallError::Unavailable(e.to_string()))?;
            Ok(format!(
                "# Written by `tornect install`; `tornect uninstall` removes it.\n\
                 [Desktop Entry]\n\
                 Type=Application\n\
                 Name={ENTRY_NAME}\n\
                 Exec={exec}\n"
            ))
        }

        /// Checks what [`Self::install`] would write, writing nothing: both
        /// folders are absolute, the menu entry's `Exec` quotes, and the bin
        /// folder (while it does not exist, the nearest folder above it that
        /// does) passes the location rule.
        pub fn preflight(&self, home: Option<&Path>) -> Result<(), InstallError> {
            for dir in [&self.bin_dir, &self.apps_dir] {
                if !dir.is_absolute() {
                    return Err(InstallError::Unavailable(format!(
                        "{} is not an absolute path",
                        dir.display()
                    )));
                }
            }
            self.menu_entry_text(home)?;
            self.location_ok(nearest_existing(&self.bin_dir))
        }

        /// Copy `source` (this program, read from the handle the command
        /// opened first) to [`Self::exe`] and write the menu entry. Refused
        /// before anything is written by [`Self::preflight`]'s checks; the bin
        /// folder is checked again once it exists. A menu entry that cannot
        /// be written removes the copy again; a folder this call created and
        /// a refusal left empty is removed too.
        pub fn install(
            &self,
            source: &mut dyn std::io::Read,
            home: Option<&Path>,
        ) -> Result<(), InstallError> {
            self.preflight(home)?;
            let entry = self.menu_entry_text(home)?;
            let mut created = create_dirs(&self.bin_dir)?;
            let copied = self.location_ok(&self.bin_dir).and_then(|()| {
                write_new(&self.bin_dir, LINUX_EXE, 0o755, &mut |f| {
                    std::io::copy(&mut *source, f).map(drop)
                })
            });
            if let Err(e) = copied {
                remove_empty(&created);
                return Err(e);
            }
            let written = create_dirs(&self.apps_dir).and_then(|dirs| {
                created.extend(dirs);
                write_new(&self.apps_dir, MENU_ENTRY, 0o644, &mut |f| {
                    f.write_all(entry.as_bytes())
                })
            });
            if let Err(e) = written {
                let _ = std::fs::remove_file(self.exe());
                remove_empty(&created);
                return Err(e);
            }
            Ok(())
        }

        /// Whether anything [`Self::install`] writes is at its name.
        #[must_use]
        pub fn installed(&self) -> bool {
            [self.menu_entry(), self.exe()]
                .iter()
                .any(|p| std::fs::symlink_metadata(p).is_ok())
        }

        /// Remove the menu entry, then the executable: regular files only,
        /// anything else at those names left and reported. Removing nothing
        /// changes nothing.
        pub fn uninstall(&self) -> Result<Removal, InstallError> {
            let mut done = Removal::default();
            for path in [self.menu_entry(), self.exe()] {
                match std::fs::symlink_metadata(&path) {
                    Ok(m) if m.file_type().is_file() => {
                        std::fs::remove_file(&path).map_err(|e| {
                            InstallError::Failed(format!("removing {}: {e}", path.display()))
                        })?;
                        done.removed.push(path);
                    }
                    Ok(_) => done.left.push(path),
                    Err(e) if e.kind() == ErrorKind::NotFound => {}
                    Err(e) => {
                        return Err(InstallError::Failed(format!(
                            "reading {}: {e}",
                            path.display()
                        )));
                    }
                }
            }
            Ok(done)
        }

        /// This process's ids and the real `stat`, or the tests'.
        fn facts(&self) -> Result<Facts, InstallError> {
            #[cfg(test)]
            if let Some(facts) = self.facts {
                return Ok(facts);
            }
            let status = std::fs::read_to_string("/proc/self/status").map_err(|e| {
                InstallError::Unavailable(format!("could not read who this process runs as: {e}"))
            })?;
            let (uid, gid) = parse_status_ids(&status).ok_or_else(|| {
                InstallError::Unavailable("/proc/self/status names no user or group".to_owned())
            })?;
            Ok(Facts {
                uid,
                gid,
                stat: real_stat,
            })
        }

        /// The location rule of the start at login for `dir` and every
        /// folder above it.
        fn location_ok(&self, dir: &Path) -> Result<(), InstallError> {
            let facts = self.facts()?;
            unix_exe_location_ok(dir, facts.uid, facts.gid, &facts.stat).map_err(|e| {
                let why = match &e {
                    AutostartError::Unavailable(why)
                    | AutostartError::Unquotable(why)
                    | AutostartError::Failed(why) => why.clone(),
                    AutostartError::Cancelled => e.to_string(),
                };
                InstallError::Refused(format!("{FOLDER_OTHERS_CAN_CHANGE} ({why})"))
            })
        }
    }

    /// `dir`, or the nearest folder above it that exists.
    fn nearest_existing(dir: &Path) -> &Path {
        dir.ancestors()
            .find(|p| std::fs::symlink_metadata(p).is_ok())
            .unwrap_or(dir)
    }

    /// Create `dir` and the folders above it that are missing (mode 0755
    /// before the umask); the ones created, from the top.
    fn create_dirs(dir: &Path) -> Result<Vec<PathBuf>, InstallError> {
        let missing: Vec<&Path> = dir
            .ancestors()
            .take_while(|p| std::fs::symlink_metadata(p).is_err())
            .collect();
        let mut created = Vec::new();
        for path in missing.into_iter().rev() {
            if let Err(e) = std::fs::DirBuilder::new().mode(0o755).create(path) {
                remove_empty(&created);
                return Err(InstallError::Failed(format!(
                    "creating {}: {e}",
                    path.display()
                )));
            }
            created.push(path.to_path_buf());
        }
        Ok(created)
    }

    /// Remove the folders `create_dirs` made, deepest first, where still
    /// empty.
    fn remove_empty(created: &[PathBuf]) {
        for path in created.iter().rev() {
            let _ = std::fs::remove_dir(path);
        }
    }

    /// Write `name` in `dir` with `mode`: into a new temporary file beside it
    /// (never one that exists, so never through a link), then renamed over
    /// the name, which replaces a link there rather than following it.
    fn write_new(
        dir: &Path,
        name: &str,
        mode: u32,
        fill: &mut dyn FnMut(&mut std::fs::File) -> std::io::Result<()>,
    ) -> Result<(), InstallError> {
        let target = dir.join(name);
        let tmp = dir.join(format!(".{name}.tmp"));
        let failed =
            |e: std::io::Error| InstallError::Failed(format!("writing {}: {e}", target.display()));
        match std::fs::remove_file(&tmp) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(failed(e)),
        }
        let written = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)
            .and_then(|mut f| {
                fill(&mut f)?;
                f.set_permissions(std::fs::Permissions::from_mode(mode))?;
                f.sync_all()
            });
        if let Err(e) = written {
            let _ = std::fs::remove_file(&tmp);
            return Err(failed(e));
        }
        std::fs::rename(&tmp, &target).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            failed(e)
        })
    }

    #[cfg(test)]
    mod tests {
        use std::collections::BTreeSet;
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        use super::*;

        const UID: u32 = 1000;
        const GID: u32 = 1000;
        const PROGRAM: &[u8] = b"\x7fELF the program";

        /// Every folder this user's, 0755.
        fn owned(_: &Path) -> std::io::Result<PathFacts> {
            Ok(PathFacts {
                uid: UID,
                gid: GID,
                mode: 0o40755,
                symlink: false,
            })
        }

        /// As [`owned`], but every folder named `.local` can be changed by
        /// every account.
        fn others_can_write_local(path: &Path) -> std::io::Result<PathFacts> {
            let mut facts = owned(path)?;
            if path.file_name().is_some_and(|n| n == ".local") {
                facts.mode = 0o40777;
            }
            Ok(facts)
        }

        struct Tree {
            _tmp: tempfile::TempDir,
            root: PathBuf,
        }

        impl Tree {
            fn new() -> Self {
                let tmp = tempfile::tempdir().unwrap();
                let root = tmp.path().to_path_buf();
                Self { _tmp: tmp, root }
            }

            fn install(&self) -> LinuxInstall {
                LinuxInstall::new(
                    self.root.join("home/.local/bin"),
                    self.root.join("home/.local/share/applications"),
                )
                .with_facts(UID, GID, owned)
            }

            /// Every file and link under the root, relative to it.
            fn files(&self) -> BTreeSet<String> {
                fn walk(dir: &Path, root: &Path, out: &mut BTreeSet<String>) {
                    for entry in std::fs::read_dir(dir).unwrap() {
                        let path = entry.unwrap().path();
                        let kind = std::fs::symlink_metadata(&path).unwrap().file_type();
                        if kind.is_dir() {
                            walk(&path, root, out);
                        } else {
                            out.insert(path.strip_prefix(root).unwrap().display().to_string());
                        }
                    }
                }
                let mut out = BTreeSet::new();
                walk(&self.root, &self.root, &mut out);
                out
            }
        }

        fn set(items: &[&str]) -> BTreeSet<String> {
            items.iter().map(|s| (*s).to_owned()).collect()
        }

        /// §B.1.1: the Linux install writes the executable into the bin
        /// folder it was given and the menu entry into the applications
        /// folder it was given, and nothing else anywhere; the entry holds
        /// the keys `Type`, `Name` and `Exec` only.
        #[test]
        fn linux_install_writes_only_the_injected_dirs() {
            let tree = Tree::new();
            let install = tree.install();
            install
                .install(&mut std::io::Cursor::new(PROGRAM), None)
                .unwrap();
            assert_eq!(
                tree.files(),
                set(&[
                    "home/.local/bin/tornect",
                    "home/.local/share/applications/tornect.desktop"
                ])
            );
            assert_eq!(std::fs::read(install.exe()).unwrap(), PROGRAM);
            let mode = std::fs::metadata(install.exe())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o755, "{mode:o}");
            let entry = std::fs::read_to_string(install.menu_entry()).unwrap();
            let exe = install.exe();
            assert_eq!(
                entry,
                format!(
                    "# Written by `tornect install`; `tornect uninstall` removes it.\n\
                     [Desktop Entry]\nType=Application\nName=Tornect\nExec=\"{}\"\n",
                    exe.display()
                )
            );
            let keys: Vec<&str> = entry
                .lines()
                .filter(|l| !l.starts_with('#') && !l.starts_with('['))
                .filter_map(|l| l.split_once('=').map(|(k, _)| k))
                .collect();
            assert_eq!(keys, ["Type", "Name", "Exec"]);
            assert!(install.installed());
        }

        /// The location rule of the start at login (M1-53): a bin folder that
        /// another account can change, or one below such a folder, is refused
        /// before anything is written or created.
        #[test]
        fn an_install_others_can_write_is_refused() {
            let tree = Tree::new();
            std::fs::create_dir_all(tree.root.join("home/.local")).unwrap();
            let install = tree.install().with_facts(UID, GID, others_can_write_local);
            let refused = |install: &LinuxInstall| match install
                .install(&mut std::io::Cursor::new(PROGRAM), None)
            {
                Err(InstallError::Refused(why)) => {
                    assert!(why.starts_with(FOLDER_OTHERS_CAN_CHANGE), "{why}");
                    assert!(why.contains("can be changed by every account"), "{why}");
                }
                other => panic!("installed below a folder others can change: {other:?}"),
            };
            // The bin folder not there yet: the folder above it is checked.
            refused(&install);
            assert!(!tree.root.join("home/.local/bin").exists());
            assert!(tree.files().is_empty(), "{:?}", tree.files());
            // The bin folder there.
            std::fs::create_dir_all(tree.root.join("home/.local/bin")).unwrap();
            refused(&install);
            assert!(tree.files().is_empty(), "{:?}", tree.files());
            assert!(matches!(
                install.preflight(None),
                Err(InstallError::Refused(_))
            ));
        }

        /// A link at the executable's name, at the menu entry's name or at
        /// the temporary file's name is replaced, never followed: what it
        /// points at stays as it was. Uninstalling leaves a link where the
        /// executable was, and says so.
        #[test]
        fn an_existing_link_is_never_followed() {
            let tree = Tree::new();
            let install = tree.install();
            let bin = tree.root.join("home/.local/bin");
            let apps = tree.root.join("home/.local/share/applications");
            std::fs::create_dir_all(&bin).unwrap();
            std::fs::create_dir_all(&apps).unwrap();
            for victim in ["victim-exe", "victim-entry", "victim-tmp", "victim-tmp2"] {
                std::fs::write(tree.root.join(victim), b"victim").unwrap();
            }
            symlink(tree.root.join("victim-exe"), bin.join("tornect")).unwrap();
            symlink(tree.root.join("victim-entry"), apps.join("tornect.desktop")).unwrap();
            symlink(tree.root.join("victim-tmp"), bin.join(".tornect.tmp")).unwrap();
            symlink(
                tree.root.join("victim-tmp2"),
                apps.join(".tornect.desktop.tmp"),
            )
            .unwrap();
            install
                .install(&mut std::io::Cursor::new(PROGRAM), None)
                .unwrap();
            for victim in ["victim-exe", "victim-entry", "victim-tmp", "victim-tmp2"] {
                assert_eq!(std::fs::read(tree.root.join(victim)).unwrap(), b"victim");
            }
            for path in [install.exe(), install.menu_entry()] {
                let kind = std::fs::symlink_metadata(&path).unwrap().file_type();
                assert!(kind.is_file(), "{} is not a regular file", path.display());
            }
            assert_eq!(std::fs::read(install.exe()).unwrap(), PROGRAM);
            assert!(!bin.join(".tornect.tmp").exists());
            std::fs::remove_file(install.exe()).unwrap();
            symlink(tree.root.join("victim-exe"), install.exe()).unwrap();
            let removal = install.uninstall().unwrap();
            assert_eq!(removal.removed, [install.menu_entry()]);
            assert_eq!(removal.left, [install.exe()]);
            assert_eq!(
                std::fs::read(tree.root.join("victim-exe")).unwrap(),
                b"victim"
            );
        }

        /// The menu entry's `Exec` goes through the start-at-sign-in entry's
        /// quoting: every item quoted, `%` written `%%`, a custom home
        /// carried as `--home`; a control character in a path, or a relative
        /// home, refuses the install before anything is written or created.
        #[test]
        fn the_menu_entry_exec_is_quoted_or_refused() {
            let tree = Tree::new();
            let install = LinuxInstall::new(
                tree.root.join("home/50% off/bin"),
                tree.root.join("home/apps"),
            )
            .with_facts(UID, GID, owned);
            let home = tree.root.join("my home");
            install
                .install(&mut std::io::Cursor::new(PROGRAM), Some(&home))
                .unwrap();
            let entry = std::fs::read_to_string(install.menu_entry()).unwrap();
            let exec = format!(
                "Exec=\"{}/home/50%% off/bin/tornect\" \"--home\" \"{}/my home\"",
                tree.root.display(),
                tree.root.display()
            );
            assert!(entry.lines().any(|l| l == exec), "{entry}");
            let bad = LinuxInstall::new(
                tree.root.join("home/new\nline/bin"),
                tree.root.join("home/apps2"),
            )
            .with_facts(UID, GID, owned);
            match bad.install(&mut std::io::Cursor::new(PROGRAM), None) {
                Err(InstallError::Unavailable(why)) => {
                    assert!(why.contains("control character"), "{why}");
                }
                other => panic!("an unquotable path was written: {other:?}"),
            }
            for dir in ["home/new\nline", "home/apps2"] {
                assert!(!tree.root.join(dir).exists(), "{dir:?} was created");
            }
            let relative = LinuxInstall::new(tree.root.join("home/bin3"), tree.root.join("a3"))
                .with_facts(UID, GID, owned);
            assert!(matches!(
                relative.install(
                    &mut std::io::Cursor::new(PROGRAM),
                    Some(Path::new("relative/home"))
                ),
                Err(InstallError::Unavailable(_))
            ));
            assert!(!tree.root.join("home/bin3").exists());
        }

        /// Uninstalling removes the menu entry and the executable it wrote,
        /// and nothing else in either folder.
        #[test]
        fn uninstall_removes_exactly_what_install_wrote() {
            let tree = Tree::new();
            let install = tree.install();
            install
                .install(&mut std::io::Cursor::new(PROGRAM), None)
                .unwrap();
            std::fs::write(tree.root.join("home/.local/bin/other-tool"), b"x").unwrap();
            std::fs::write(
                tree.root
                    .join("home/.local/share/applications/other.desktop"),
                b"x",
            )
            .unwrap();
            let removal = install.uninstall().unwrap();
            assert_eq!(removal.removed, [install.menu_entry(), install.exe()]);
            assert!(removal.left.is_empty());
            assert_eq!(
                tree.files(),
                set(&[
                    "home/.local/bin/other-tool",
                    "home/.local/share/applications/other.desktop"
                ])
            );
            assert!(!install.installed());
        }

        /// Uninstalling where nothing was installed removes nothing and
        /// creates nothing.
        #[test]
        fn uninstalling_nothing_is_a_no_op() {
            let tree = Tree::new();
            let install = tree.install();
            assert!(!install.installed());
            assert_eq!(install.uninstall().unwrap(), Removal::default());
            assert_eq!(std::fs::read_dir(&tree.root).unwrap().count(), 0);
        }
    }
}
