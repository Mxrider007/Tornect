//! The administrator helper's pipe and checks (`docs/PLAN.md` §B.8.7.5; r7,
//! M-FEAT-3): the per-session pipe name, the helper's command line, and the
//! decisions both ends take about the process at the other end.
//!
//! The decisions are pure functions over the facts read, tested here on
//! every system; the reads themselves (the pipe with its explicit DACL, the
//! client and server process ids, their images, tokens and sessions, the
//! UAC launch, the host-exit watch and the panic-chord hook) are Windows
//! calls in `win_helper`, type-checked only on this build machine
//! (NEEDS-DEVICE(windows)).
//!
//! What the checks keep out: other users, other sessions, network clients
//! and foreign binaries. They do not keep out code running as the same
//! user, which can drive the host itself (the residual of §B.8.7.5, T9).

use std::ffi::OsString;
use std::time::Duration;

/// Every helper pipe's name starts so; 32 lowercase hex digits follow.
pub const PIPE_PREFIX: &str = r"\\.\pipe\tornect-helper-";

/// How long the host waits, after Windows started the helper, for it to
/// connect, pass the host's check and say it is ready (§B.2.1: the level is
/// fixed at `SESSION_ACCEPT`; a helper later than this is never attached).
pub const BUDGET: Duration = Duration::from_secs(5);

/// The pipe name for 16 random bytes (128 bits, H4).
#[must_use]
pub fn pipe_name(random: &[u8; 16]) -> String {
    let mut name = String::with_capacity(PIPE_PREFIX.len() + 32);
    name.push_str(PIPE_PREFIX);
    for b in random {
        name.push_str(&format!("{b:02x}"));
    }
    name
}

/// A fresh, unguessable pipe name (H4).
pub fn new_pipe_name() -> std::io::Result<String> {
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(pipe_name(&random))
}

/// Whether `name` is a helper pipe name as [`pipe_name`] writes it.
#[must_use]
pub fn valid_pipe_name(name: &str) -> bool {
    name.strip_prefix(PIPE_PREFIX).is_some_and(|hex| {
        hex.len() == 32 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

/// What `tornect input-helper` is started with, and nothing else: no
/// config, no environment, no file (H2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperArgs {
    /// The per-session pipe the host created.
    pub pipe: String,
    /// The host's process id: the pipe's server must be it, and the helper
    /// exits when it exits.
    pub host_pid: u32,
    /// The hard cap (§B.8.7.5: the session maximum, or 12 h).
    pub hard_cap: Duration,
}

impl HelperArgs {
    /// The command line after `input-helper`, as the host writes it.
    #[must_use]
    pub fn to_args(&self) -> Vec<String> {
        vec![
            self.pipe.clone(),
            self.host_pid.to_string(),
            self.hard_cap.as_secs().to_string(),
        ]
    }

    /// Parse exactly `<pipe> <host pid> <cap s>`: a helper pipe name, a
    /// process id, and a cap of 1 s to 12 h. Anything else is refused.
    pub fn parse(args: &[OsString]) -> Result<Self, &'static str> {
        let [pipe, pid, cap] = args else {
            return Err("three arguments: <pipe> <host pid> <limit s>");
        };
        let pipe = pipe
            .to_str()
            .filter(|p| valid_pipe_name(p))
            .ok_or("the pipe name")?;
        let host_pid = pid
            .to_str()
            .and_then(|p| p.parse::<u32>().ok())
            .filter(|p| *p != 0)
            .ok_or("the host's process id")?;
        let hard_cap = cap
            .to_str()
            .and_then(|c| c.parse::<u64>().ok())
            .filter(|c| (1..=MAX_CAP_SECS).contains(c))
            .map(Duration::from_secs)
            .ok_or("the time limit")?;
        Ok(Self {
            pipe: pipe.to_owned(),
            host_pid,
            hard_cap,
        })
    }
}

/// 12 h, the longest a helper may live (§B.8.7.5).
pub const MAX_CAP_SECS: u64 = 12 * 3600;

/// What the helper read about the process at the other end of its pipe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerFacts {
    /// `GetNamedPipeServerProcessId`.
    pub pid: u32,
    /// Its executable's full path, when it could be read.
    pub image: Option<String>,
    /// Its Windows session id, when it could be read.
    pub session: Option<u32>,
    /// Whether its executable is the same file as the helper's own — the
    /// volume serial number and file index of both, opened — when that
    /// could be read (review F-10).
    pub same_file: Option<bool>,
}

/// What the helper knows about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperSelf {
    /// Its own executable's full path, as the open file resolves it
    /// (`GetFinalPathNameByHandleW`; review F-10).
    pub image: String,
    /// Its own Windows session id.
    pub session: u32,
    /// The Program Files folder, from `FOLDERID_ProgramFiles`.
    pub program_files: String,
}

/// Whether two executable paths name the same file as Windows reports
/// them: equal ignoring ASCII case (NTFS paths are case-insensitive).
#[must_use]
pub fn same_image(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// The helper's check of the pipe's server (§B.8.7.5; amendment §1.3 (e)):
/// the process id it was given, the same executable as itself, which lies
/// under Program Files, and the same Windows session. A fact that could not
/// be read refuses.
pub fn check_server(
    host_pid: u32,
    me: &HelperSelf,
    server: &ServerFacts,
) -> Result<(), &'static str> {
    if server.pid != host_pid {
        return Err("the pipe's server is not the process that started this helper");
    }
    // Where this helper's image lies, as its open file resolves on Windows
    // (review F-10: by handle, not by the path it was started with).
    if !crate::autostart::location_under(&me.image, std::slice::from_ref(&me.program_files)) {
        return Err("this helper does not run from Program Files");
    }
    match &server.image {
        Some(image) if same_image(image, &me.image) => {}
        Some(_) => return Err("the pipe's server is another program"),
        None => return Err("the pipe's server could not be identified"),
    }
    // The same file on disk, compared by volume and file index (F-10).
    match server.same_file {
        Some(true) => {}
        Some(false) => return Err("the pipe's server runs another copy of Tornect"),
        None => return Err("the pipe's server's executable could not be compared"),
    }
    match server.session {
        Some(s) if s == me.session => Ok(()),
        Some(_) => Err("the pipe's server runs in another Windows session"),
        None => Err("the pipe's server's session could not be read"),
    }
}

/// Who the host expects at the other end of its pipe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expect {
    /// Attended: the process `ShellExecuteEx` returned.
    Launched {
        /// Its process id.
        pid: u32,
    },
    /// Unattended: the registered task's Program Files image, running
    /// elevated in the host's own session.
    Task {
        /// The registered executable's full path.
        image: String,
        /// The host's Windows session id.
        session: u32,
    },
}

/// What the host read about its pipe's client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientFacts {
    /// `GetNamedPipeClientProcessId`.
    pub pid: u32,
    /// Its executable's full path, when it could be read.
    pub image: Option<String>,
    /// Whether its token is elevated, when that could be read.
    pub elevated: Option<bool>,
    /// Its Windows session id, when it could be read.
    pub session: Option<u32>,
}

/// The host's check of its pipe's one client (§B.8.7.5; amendment §1.3 (d)).
/// Attended: the process id `ShellExecuteEx` returned. Unattended: the
/// registered image, an elevated token, the host's session. A fact that
/// could not be read refuses.
pub fn check_client(expect: &Expect, client: &ClientFacts) -> Result<(), &'static str> {
    match expect {
        Expect::Launched { pid } => {
            if client.pid == *pid {
                Ok(())
            } else {
                Err("the pipe's client is not the helper Windows started")
            }
        }
        Expect::Task { image, session } => {
            match &client.image {
                Some(got) if same_image(got, image) => {}
                Some(_) => return Err("the pipe's client is another program"),
                None => return Err("the pipe's client could not be identified"),
            }
            if client.elevated != Some(true) {
                return Err("the pipe's client does not run as administrator");
            }
            if client.session != Some(*session) {
                return Err("the pipe's client runs in another Windows session");
            }
            Ok(())
        }
    }
}

/// Why administrator access was not given for a session (§B.2.1): the
/// session sheet says "Administrator access was not given" and keeps the
/// other answers; `sessions.log` records the reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotGiven {
    /// Windows' prompt was cancelled.
    Cancelled,
    /// Windows could not start the helper (the prompt failed, a wrong
    /// password, policy).
    NotStarted,
    /// The helper did not connect, pass the check and say it was ready
    /// within [`BUDGET`]: it was ended, never attached.
    Late,
    /// The process at the other end of the pipe failed the host's check.
    Refused,
    /// The pipe could not be created (another instance exists, H4).
    NoPipe,
    /// This host cannot start the helper (not installed, not Windows).
    Unavailable,
}

impl NotGiven {
    /// In fixed words.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Cancelled => "Windows' prompt was cancelled",
            Self::NotStarted => "Windows did not start the administrator helper",
            Self::Late => "the administrator helper did not start in time",
            Self::Refused => "the process at the pipe was not the administrator helper",
            Self::NoPipe => "the helper's pipe could not be created",
            Self::Unavailable => "this computer cannot start the administrator helper",
        }
    }
}

/// The Windows end of the pipe (NEEDS-DEVICE(windows)): one helper pipe,
/// read and written a frame at a time from any thread.
#[cfg(windows)]
pub struct HelperPipe(crate::win_helper::Pipe);

#[cfg(windows)]
impl HelperPipe {
    /// The next whole frame; `None` when the pipe closed before its first
    /// byte.
    pub fn read_frame(&self) -> std::io::Result<Option<[u8; 16]>> {
        self.0.read_frame()
    }

    /// Write one frame whole.
    pub fn write_frame(&self, frame: &[u8; 16]) -> std::io::Result<()> {
        self.0.write_frame(frame)
    }

    /// End every pending read and write, and disconnect the other end.
    pub fn close(&self) {
        self.0.close();
    }
}

/// The host's pipe for one session (H4): explicit DACL (this user, plus
/// Administrators when `administrators`), one instance created first,
/// remote clients refused.
#[cfg(windows)]
pub fn create_pipe(name: &str, administrators: bool) -> std::io::Result<HelperPipe> {
    crate::win_helper::create_server(name, administrators).map(HelperPipe)
}

/// Wait up to `wait` for the pipe's one client; `false` when none came.
#[cfg(windows)]
pub fn accept_client(pipe: &HelperPipe, wait: Duration) -> std::io::Result<bool> {
    crate::win_helper::accept(&pipe.0, wait)
}

/// What the host reads about its pipe's client.
#[cfg(windows)]
pub fn client_facts(pipe: &HelperPipe) -> std::io::Result<ClientFacts> {
    crate::win_helper::client_facts(&pipe.0)
}

/// Open the host's pipe `name` as the helper (identification only: the
/// host can never impersonate the helper's token).
#[cfg(windows)]
pub fn connect_pipe(name: &str) -> std::io::Result<HelperPipe> {
    crate::win_helper::connect(name).map(HelperPipe)
}

/// What the helper reads about its pipe's server.
#[cfg(windows)]
pub fn server_facts(pipe: &HelperPipe) -> std::io::Result<ServerFacts> {
    crate::win_helper::server_facts(&pipe.0)
}

/// What the helper knows about itself: its image as Windows reports it,
/// its session, and the Program Files folder from `FOLDERID_ProgramFiles`
/// (never an environment variable).
#[cfg(windows)]
pub fn helper_self() -> std::io::Result<HelperSelf> {
    let program_files = crate::win::known_folder(crate::win::KnownFolder::ProgramFiles)?;
    Ok(HelperSelf {
        image: crate::win_helper::final_path(&crate::win_helper::own_image()?)?,
        session: crate::win_helper::own_session()?,
        program_files: program_files
            .to_str()
            .ok_or_else(|| std::io::Error::other("Program Files is not Unicode"))?
            .to_owned(),
    })
}

/// This process's executable as Windows reports it (the image the host
/// starts the helper from).
#[cfg(windows)]
pub fn own_image() -> std::io::Result<String> {
    crate::win_helper::own_image()
}

/// This process's Windows session.
#[cfg(windows)]
pub fn own_session() -> std::io::Result<u32> {
    crate::win_helper::own_session()
}

/// This process's id.
#[cfg(windows)]
#[must_use]
pub fn own_pid() -> u32 {
    crate::win_helper::own_pid()
}

/// Whether this account is an administrator (a filtered token counts):
/// on a standard account the helper runs as the administrator whose
/// password was typed, and the pipe's DACL admits Administrators.
#[cfg(windows)]
pub fn is_administrator() -> std::io::Result<bool> {
    crate::win::is_administrator()
}

/// Call `exited` once process `pid` exits.
#[cfg(windows)]
pub fn when_exits(pid: u32, exited: impl FnOnce() + Send + 'static) -> std::io::Result<()> {
    crate::win_helper::when_exits(pid, exited)
}

/// Watch for the physical panic chord Ctrl+Alt+End (the helper's own hook);
/// `pressed` is called once. `Err` when the hook could not be set.
#[cfg(windows)]
pub fn watch_panic_chord(pressed: impl FnOnce() + Send + 'static) -> std::io::Result<()> {
    crate::win_helper::watch_panic_chord(pressed)
}

/// Whether a secure Windows screen (a UAC prompt, Ctrl+Alt+Del, the lock
/// screen) is the input desktop now (§B.8.8); `None` when unreadable.
#[cfg(windows)]
#[must_use]
pub fn secure_desktop_shown() -> Option<bool> {
    crate::win_helper::secure_desktop_shown()
}

/// A helper Windows started after its prompt; ended on drop unless kept.
#[cfg(windows)]
pub struct LaunchedHelper(Option<crate::win_helper::Launched>);

#[cfg(windows)]
impl LaunchedHelper {
    /// Its process id.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.0.as_ref().map_or(0, |l| l.pid)
    }

    /// It was attached: dropping this no longer ends it (the pipe's close,
    /// `Stop` and the heartbeat do).
    pub fn keep(mut self) {
        self.0 = None;
    }
}

#[cfg(windows)]
impl Drop for LaunchedHelper {
    fn drop(&mut self) {
        if let Some(launched) = self.0.take() {
            launched.terminate();
        }
    }
}

/// Start `exe input-helper <args>` through Windows' prompt (`runas`); returns
/// once the prompt was answered and the process started.
#[cfg(windows)]
pub fn launch_helper(exe: &std::path::Path, args: &HelperArgs) -> Result<LaunchedHelper, NotGiven> {
    let line = std::iter::once("input-helper".to_owned())
        .chain(args.to_args())
        .collect::<Vec<_>>()
        .join(" ");
    match crate::win_helper::start_elevated(exe, &line) {
        Ok(launched) => Ok(LaunchedHelper(Some(launched))),
        Err(crate::win_helper::LaunchError::Cancelled) => Err(NotGiven::Cancelled),
        Err(crate::win_helper::LaunchError::Failed(e)) => {
            tracing::warn!(error = %e, "starting the administrator helper");
            Err(NotGiven::NotStarted)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pipe_name_has_128_random_bits_and_nothing_else_passes() {
        let name = pipe_name(&[0xab; 16]);
        assert_eq!(name, format!("{PIPE_PREFIX}{}", "ab".repeat(16)));
        assert!(valid_pipe_name(&name));
        let fresh = new_pipe_name().unwrap();
        assert!(valid_pipe_name(&fresh));
        assert_ne!(
            fresh,
            new_pipe_name().unwrap(),
            "unguessable, fresh each time"
        );
        for bad in [
            String::new(),
            PIPE_PREFIX.to_owned(),
            format!("{PIPE_PREFIX}{}", "AB".repeat(16)),
            format!("{PIPE_PREFIX}{}", "ab".repeat(15)),
            format!("{PIPE_PREFIX}{}0", "ab".repeat(16)),
            format!(r"\\server\pipe\tornect-helper-{}", "ab".repeat(16)),
            format!("{PIPE_PREFIX}{}g", "ab".repeat(15)),
        ] {
            assert!(!valid_pipe_name(&bad), "{bad}");
        }
    }

    #[test]
    fn the_command_line_is_exactly_pipe_pid_and_limit() {
        let args = HelperArgs {
            pipe: pipe_name(&[1; 16]),
            host_pid: 4242,
            hard_cap: Duration::from_secs(MAX_CAP_SECS),
        };
        let line: Vec<OsString> = args.to_args().into_iter().map(OsString::from).collect();
        assert_eq!(HelperArgs::parse(&line), Ok(args.clone()));
        let with = |i: usize, v: &str| {
            let mut l = line.clone();
            l[i] = OsString::from(v);
            HelperArgs::parse(&l)
        };
        assert!(with(0, "tornect-helper").is_err(), "not a helper pipe");
        assert!(with(1, "0").is_err(), "no process 0");
        assert!(with(1, "-3").is_err());
        assert!(with(1, "12x").is_err());
        assert!(with(2, "0").is_err(), "a limit of at least 1 s");
        assert!(
            with(2, &(MAX_CAP_SECS + 1).to_string()).is_err(),
            "at most 12 h"
        );
        assert!(HelperArgs::parse(&line[..2]).is_err(), "too few");
        let mut more = line.clone();
        more.push(OsString::from("--config"));
        assert!(HelperArgs::parse(&more).is_err(), "too many");
    }

    fn me() -> HelperSelf {
        HelperSelf {
            image: r"C:\Program Files\Tornect\tornect.exe".to_owned(),
            session: 1,
            program_files: r"C:\Program Files".to_owned(),
        }
    }

    /// Amendment §1.3 (e): the helper checks the pipe's server — the process
    /// it was given, the same Program Files image, the same session — and a
    /// fact it could not read refuses.
    #[test]
    fn the_helper_refuses_a_wrong_server() {
        let good = ServerFacts {
            pid: 4242,
            image: Some(r"c:\program files\tornect\TORNECT.EXE".to_owned()),
            session: Some(1),
            same_file: Some(true),
        };
        assert_eq!(check_server(4242, &me(), &good), Ok(()));
        let cases = [
            (4243, good.clone(), "another process"),
            (
                4242,
                ServerFacts {
                    image: Some(r"C:\Users\a\tornect.exe".to_owned()),
                    ..good.clone()
                },
                "another image",
            ),
            (
                4242,
                ServerFacts {
                    image: None,
                    ..good.clone()
                },
                "image unread",
            ),
            (
                4242,
                ServerFacts {
                    session: Some(2),
                    ..good.clone()
                },
                "another session",
            ),
            (
                4242,
                ServerFacts {
                    session: None,
                    ..good.clone()
                },
                "session unread",
            ),
            (
                4242,
                ServerFacts {
                    same_file: Some(false),
                    ..good.clone()
                },
                "another file at the same path",
            ),
            (
                4242,
                ServerFacts {
                    same_file: None,
                    ..good.clone()
                },
                "file identity unread",
            ),
        ];
        for (pid, facts, why) in cases {
            assert!(check_server(pid, &me(), &facts).is_err(), "{why}");
        }
        let elsewhere = HelperSelf {
            image: r"C:\Users\a\Downloads\tornect.exe".to_owned(),
            ..me()
        };
        let same = ServerFacts {
            image: Some(elsewhere.image.clone()),
            ..good
        };
        assert!(
            check_server(4242, &elsewhere, &same).is_err(),
            "a helper outside Program Files never serves"
        );
    }

    /// Amendment §1.3 (d): the host checks its pipe's one client —
    /// attended, the process Windows started; unattended, the registered
    /// image, elevated, in the host's session.
    #[test]
    fn the_host_refuses_a_wrong_client() {
        let launched = Expect::Launched { pid: 77 };
        let client = ClientFacts {
            pid: 77,
            image: None,
            elevated: None,
            session: None,
        };
        assert_eq!(check_client(&launched, &client), Ok(()));
        assert!(check_client(&launched, &ClientFacts { pid: 78, ..client }).is_err());
        let task = Expect::Task {
            image: me().image,
            session: 1,
        };
        let good = ClientFacts {
            pid: 90,
            image: Some(r"C:\PROGRAM FILES\Tornect\tornect.exe".to_owned()),
            elevated: Some(true),
            session: Some(1),
        };
        assert_eq!(check_client(&task, &good), Ok(()));
        for (facts, why) in [
            (
                ClientFacts {
                    image: Some(r"C:\x\tornect.exe".to_owned()),
                    ..good.clone()
                },
                "image",
            ),
            (
                ClientFacts {
                    image: None,
                    ..good.clone()
                },
                "image unread",
            ),
            (
                ClientFacts {
                    elevated: Some(false),
                    ..good.clone()
                },
                "not elevated",
            ),
            (
                ClientFacts {
                    elevated: None,
                    ..good.clone()
                },
                "elevation unread",
            ),
            (
                ClientFacts {
                    session: Some(3),
                    ..good.clone()
                },
                "session",
            ),
            (
                ClientFacts {
                    session: None,
                    ..good.clone()
                },
                "session unread",
            ),
        ] {
            assert!(check_client(&task, &facts).is_err(), "{why}");
        }
    }

    #[test]
    fn every_reason_is_fixed_words() {
        for n in [
            NotGiven::Cancelled,
            NotGiven::NotStarted,
            NotGiven::Late,
            NotGiven::Refused,
            NotGiven::NoPipe,
            NotGiven::Unavailable,
        ] {
            assert!(!n.reason().is_empty());
        }
    }
}
