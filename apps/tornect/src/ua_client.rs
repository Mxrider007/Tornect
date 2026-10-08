//! The unattended client (`docs/PLAN.md` §B.8.10, §B.8.9.1): what the window and
//! `tornect connect --unattended` share — `hosts.toml` as the pin of the host's OPAQUE
//! key, the remembered passwords, the words for every way an attempt ends, and the
//! client's `sessions.log` line.
//!
//! One attempt is one explicit action of the person: nothing here retries, whatever
//! the error. The suite is the build's constant (the FSM's); the words keep "could not
//! reach the host" apart from "wrong password", and only a refused password makes a
//! remembered one stale.

use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use tornect_core::session_log::{SessionEvent, SessionLog, SessionMode, SessionRecord};
use tornect_core::trusted::KnownHost;
use tornect_core::unattended::credentials::{Attempt, Deleted, SavedPasswords, Settled};
use tornect_core::unattended::hosts::{HostsFile, PinCheck};
use tornect_core::{DeviceId, Paths, TornectId};
use tornect_signal::envelope::codes;
use tornect_signal::fsm::HandshakeError;
use tornect_signal::fsm::client::ServerKeyPin;
use tornect_signal::messages::{self, SessionReject, cause, reject};
use zeroize::Zeroizing;

/// This computer's remembered passwords for `device`: its OS keychain when one is
/// usable (Windows Credential Manager, the Linux kernel keyrings), else none.
#[must_use]
pub fn system_passwords(device: &tornect_core::DeviceIdentity) -> SavedPasswords {
    SavedPasswords::new(
        tornect_core::unattended::credentials::system_vault(),
        *device.id().public_key_bytes(),
    )
}

/// Refuse a password given on the command line or in the environment (§B.8.7.4:
/// passwords through the terminal's prompt only), saying why.
pub fn refuse_password_sources(
    on_command_line: bool,
    vars: impl IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
) -> anyhow::Result<()> {
    if on_command_line {
        anyhow::bail!(
            "Tornect never takes a password on the command line: other programs on this \
             computer can read a command line, and shells keep it in their history. Leave \
             --password out; `tornect connect <id> --unattended` asks for it on the terminal."
        );
    }
    for (name, _) in vars {
        let name = name.to_string_lossy().to_ascii_uppercase();
        if name.starts_with("TORNECT") && name.contains("PASSWORD") {
            anyhow::bail!(
                "Tornect never takes a password from the environment ({name}): programs of this \
                 user can read a process's environment, and it is easily inherited or logged. \
                 Unset it; `tornect connect <id> --unattended` asks for the password on the \
                 terminal."
            );
        }
    }
    Ok(())
}

/// How long an operation on `hosts.toml` waits for another Tornect that holds the
/// lock beside it, so that a stuck process never stalls this one without bound.
const HOSTS_LOCK_WAIT: Duration = Duration::from_secs(10);

/// How often the lock beside `hosts.toml` is tried again while another Tornect
/// holds it.
const HOSTS_LOCK_RETRY: Duration = Duration::from_millis(50);

/// What an operation on `hosts.toml` fails with when another Tornect held the lock
/// beside it for all of [`HOSTS_LOCK_WAIT`].
const HOSTS_LOCK_HELD: &str =
    "another Tornect held the lock beside hosts.toml for more than 10 s; nothing was saved";

const _: () = assert!(HOSTS_LOCK_WAIT.as_secs() == 10, "the text names the wait");

/// One writer of `hosts.toml` at a time (§B.8.9.1): in this process the FSM's pin
/// and the remembered-password bookkeeping both load, change and save it, and the
/// window and a command line are two processes that do the same. The guard holds
/// this process's mutex, and the OS lock on `hosts.toml.lock` beside the file when
/// it could be taken ([`HostsLock::held`]); both are released when it drops. The
/// lock orders the saves, not the answers.
struct HostsLock {
    _process: MutexGuard<'static, ()>,
    file: Result<std::fs::File, String>,
}

impl HostsLock {
    /// The OS lock is held, so `hosts.toml` may be read and saved; otherwise why
    /// not, and the caller's operation fails with it.
    fn held(&self) -> anyhow::Result<()> {
        match &self.file {
            Ok(_) => Ok(()),
            Err(why) => Err(anyhow::anyhow!("{why}")),
        }
    }
}

/// This process's mutex, then the OS lock beside `hosts_file` (§B.8.9.1).
fn hosts_lock(hosts_file: &std::path::Path) -> HostsLock {
    static LOCK: Mutex<()> = Mutex::new(());
    let process = LOCK.lock().unwrap_or_else(PoisonError::into_inner);
    HostsLock {
        _process: process,
        file: lock_file(hosts_file, HOSTS_LOCK_WAIT),
    }
}

/// The OS lock on `hosts.toml.lock` beside `hosts_file`: the file created if missing
/// (this account's only), locked exclusively, tried every [`HOSTS_LOCK_RETRY`] for at
/// most `wait`; released when the returned file is dropped. A lock that cannot be
/// opened or taken is an error, never a way around it.
fn lock_file(hosts_file: &std::path::Path, wait: Duration) -> Result<std::fs::File, String> {
    let not_taken = |e: &dyn std::fmt::Display| {
        format!("the lock beside hosts.toml could not be taken ({e}); nothing was saved")
    };
    if let Some(dir) = hosts_file.parent().filter(|dir| !dir.exists()) {
        tornect_core::keystore::create_private_dir(dir).map_err(|e| not_taken(&e))?;
    }
    let mut name = hosts_file.as_os_str().to_owned();
    name.push(".lock");
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let file = options.open(&name).map_err(|e| not_taken(&e))?;
    let until = Instant::now() + wait;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(std::fs::TryLockError::WouldBlock) if Instant::now() < until => {
                std::thread::sleep(HOSTS_LOCK_RETRY);
            }
            Err(std::fs::TryLockError::WouldBlock) => return Err(HOSTS_LOCK_HELD.to_owned()),
            Err(std::fs::TryLockError::Error(e)) => return Err(not_taken(&e)),
        }
    }
}

/// `hosts.toml` as the FSM's pin of the host's OPAQUE key (§B.8.9, A16): checked
/// before the proof on every login, recorded at the first accept with the build's
/// suite. A file that cannot be read fails closed (a mismatch: no proof is sent).
#[derive(Debug)]
pub struct HostsPin {
    path: std::path::PathBuf,
}

impl HostsPin {
    /// The pin of the home `paths`.
    #[must_use]
    pub fn new(paths: &Paths) -> Self {
        Self {
            path: paths.hosts_file(),
        }
    }
}

impl ServerKeyPin for HostsPin {
    fn check(&self, host: &TornectId, server_s_pk: &[u8; 32]) -> PinCheck {
        let one = hosts_lock(&self.path);
        // A lock not taken is an unreadable file: never "no pin yet", which would
        // trust a new host key.
        if let Err(e) = one.held() {
            tracing::warn!(error = %e, "hosts.toml could not be read: the host's key cannot be checked");
            return PinCheck::Mismatch;
        }
        match HostsFile::load(&self.path) {
            Ok(file) => file.check_pin(host, server_s_pk),
            Err(e) => {
                tracing::warn!(error = %e, "hosts.toml could not be read: the host's key cannot be checked");
                PinCheck::Mismatch
            }
        }
    }

    fn record(&self, host: &TornectId, server_s_pk: &[u8; 32]) {
        let one = hosts_lock(&self.path);
        if let Err(e) = one.held() {
            tracing::warn!(error = %e, "hosts.toml could not be saved");
            return;
        }
        let saved = HostsFile::load(&self.path).and_then(|mut file| {
            if file
                .record_success(host, *server_s_pk, tornect_signal::auth::SUITE_OPAQUE)
                .is_err()
            {
                tracing::warn!("the host's key changed between the check and the accept");
                return Ok(());
            }
            file.save(&self.path)
        });
        if let Err(e) = saved {
            tracing::warn!(error = %e, "hosts.toml could not be saved");
        }
    }
}

/// This home's saved unattended record of `host`, if any (the prompt reads it:
/// whether a password is remembered, stale, and whether the grant may carry the
/// administrator level).
#[must_use]
pub fn record(paths: &Paths, host: &TornectId) -> tornect_core::unattended::hosts::HostRecord {
    let one = hosts_lock(&paths.hosts_file());
    if let Err(e) = one.held() {
        tracing::warn!(error = %e, "hosts.toml could not be read");
        return tornect_core::unattended::hosts::HostRecord::default();
    }
    HostsFile::load(&paths.hosts_file())
        .ok()
        .and_then(|f| f.get(host).cloned())
        .unwrap_or_default()
}

/// The remembered password of `host`, if one is kept and the keychain still has it.
pub fn recall(
    paths: &Paths,
    saved: &SavedPasswords,
    host: &TornectId,
) -> anyhow::Result<Option<Zeroizing<String>>> {
    let one = hosts_lock(&paths.hosts_file());
    one.held()?;
    let file = HostsFile::load(&paths.hosts_file())?;
    Ok(saved.recall(&file, host)?)
}

/// What the keychain gave for an attempt about to be made ([`recall_for_use`]).
pub enum Recalled {
    /// The remembered password.
    Password(Zeroizing<String>),
    /// `hosts.toml` said a password was remembered and the keychain has none (a restart
    /// empties the Linux kernel keyrings): the flag is cleared, the password must be typed.
    Vanished,
    /// No password is remembered.
    Nothing,
}

/// The remembered password of `host` for the attempt about to be made; a flag whose
/// keychain entry is gone is cleared on the way, so that no prompt announces a remembered
/// password again (I-9). Without a usable keychain the flag stays as it is.
pub fn recall_for_use(
    paths: &Paths,
    saved: &SavedPasswords,
    host: &TornectId,
) -> anyhow::Result<Recalled> {
    if let Some(password) = recall(paths, saved, host)? {
        return Ok(Recalled::Password(password));
    }
    let path = paths.hosts_file();
    let one = hosts_lock(&path);
    one.held()?;
    let mut file = HostsFile::load(&path)?;
    // Kept meanwhile by another attempt of this process: used, not cleared.
    if let Some(password) = saved.recall(&file, host)? {
        return Ok(Recalled::Password(password));
    }
    if saved.keychain().is_none() || !file.get(host).is_some_and(|r| r.remember) {
        return Ok(Recalled::Nothing);
    }
    file.entry(host).remember = false;
    file.save(&path)?;
    Ok(Recalled::Vanished)
}

/// What [`forget`] could not do, so that nobody is told the password went when it did not
/// (FR2-L1).
#[derive(Debug)]
pub enum Kept {
    /// The keychain refused the delete: the remembered password may still be there.
    Password(anyhow::Error),
    /// `hosts.toml` could not be read or written: its record stayed (the password went).
    Record(anyhow::Error),
}

impl std::fmt::Display for Kept {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password(e) => write!(f, "the remembered password could not be deleted: {e:#}"),
            Self::Record(e) => write!(
                f,
                "the remembered password was deleted, but hosts.toml could not be updated: {e:#}"
            ),
        }
    }
}

impl std::error::Error for Kept {}

/// Forget `host`'s unattended record and delete its remembered password (Forget). The
/// keychain entry goes first, by its derived name, so that a `hosts.toml` that cannot be
/// read never keeps the password (F4-L2).
pub fn forget(paths: &Paths, saved: &SavedPasswords, host: &TornectId) -> Result<(), Kept> {
    let one = hosts_lock(&paths.hosts_file());
    saved.erase(host).map_err(|e| Kept::Password(e.into()))?;
    one.held().map_err(Kept::Record)?;
    forget_record(&paths.hosts_file(), saved, host).map_err(Kept::Record)
}

/// `host`'s record in the `hosts.toml` at `path` goes (its flag first).
fn forget_record(
    path: &std::path::Path,
    saved: &SavedPasswords,
    host: &TornectId,
) -> anyhow::Result<()> {
    let mut file = HostsFile::load(path)?;
    saved.forget(&mut file, host)?;
    if file.remove(host) {
        file.save(path)?;
    }
    Ok(())
}

/// Delete every remembered password of this home (Rotate ID): the derived entry of every
/// host in `hosts.toml` and `known-hosts.toml`, whatever its `remember` flag says (F4-5),
/// then the flags; how many entries were there. A file that cannot be read is reported
/// after the entries of the other one went.
pub fn forget_all(paths: &Paths, saved: &SavedPasswords) -> anyhow::Result<usize> {
    let path = paths.hosts_file();
    let one = hosts_lock(&path);
    let file = HostsFile::load(&path);
    let known =
        tornect_core::trusted::KnownHosts::load(&tornect_core::trusted::known_hosts_file(paths));
    let mut hosts: Vec<TornectId> = Vec::new();
    if let Ok(file) = &file {
        hosts.extend(
            file.hosts
                .keys()
                .filter_map(|onion| onion.parse::<TornectId>().ok()),
        );
    }
    if let Ok(known) = &known {
        hosts.extend(known.hosts.keys().copied());
    }
    hosts.sort();
    hosts.dedup();
    let mut gone = 0;
    for host in &hosts {
        if saved.erase(host)? {
            gone += 1;
        }
    }
    one.held()?;
    let mut file = file?;
    let mut changed = false;
    for record in file.hosts.values_mut() {
        changed |= std::mem::take(&mut record.remember);
    }
    if changed {
        file.save(&path)?;
    }
    known?;
    Ok(gone)
}

/// What the person chose in the prompt, for one attempt.
pub struct Request {
    /// The password typed, or the remembered one.
    pub password: Zeroizing<String>,
    /// "View only this time".
    pub view_only: bool,
    /// Ask for the administrator level (offered only when the saved record says
    /// the grant may carry it; the command line's `--administrator`).
    pub administrator: bool,
    /// "Remember on this device" was ticked (and offered).
    pub remember: bool,
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("password", &"<redacted>")
            .field("view_only", &self.view_only)
            .field("administrator", &self.administrator)
            .field("remember", &self.remember)
            .finish()
    }
}

impl Request {
    /// The FSM's intent for this request.
    #[must_use]
    pub fn intent(&self) -> tornect_signal::fsm::client::Intent {
        use tornect_core::levels::Elevation;
        tornect_signal::fsm::client::Intent::Unattended(
            tornect_signal::fsm::client::UnattendedIntent {
                password: self.password.clone(),
                want_mode: if self.view_only {
                    messages::mode::VIEW_ONLY
                } else {
                    messages::mode::CONTROL
                },
                want_elevation: if self.administrator {
                    Elevation::Admin
                } else {
                    Elevation::None
                },
            },
        )
    }
}

/// How an unattended attempt ended without a session, in the person's words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ended {
    /// What it means for a remembered password.
    pub attempt: Attempt,
    /// The sentence to show (names the host: a window obeys `screen_shared`, a
    /// terminal prints it only when it is one).
    pub text: String,
    /// The outcome's name for the client's `sessions.log` line (no host in it).
    pub reason: String,
    /// The host's unattended setup changed (A16): Connect waits until the person
    /// confirms they read this.
    pub blocks: bool,
    /// The host could not be reached at all: the password was not tried.
    pub unreachable: bool,
}

/// "in 2 h 15 min", "in 40 s": a wait as people say it (capped at 24 h, §B.8.4.6).
#[must_use]
pub fn wait_text(secs: u32) -> String {
    let secs = secs.min(24 * 3600);
    match secs {
        0..=59 => format!("{secs} s"),
        60..=3599 => format!("{} min", secs.div_ceil(60)),
        _ => {
            let (h, m) = (secs / 3600, (secs % 3600) / 60);
            if m == 0 {
                format!("{h} h")
            } else {
                format!("{h} h {m} min")
            }
        }
    }
}

/// The words for a `SESSION_REJECT` of an unattended request, every code of
/// §B.8.4.6, about the host called `host`.
#[must_use]
pub fn reject_text(r: &SessionReject, host: &str) -> String {
    let wait = |s: Option<u32>| s.map(|s| format!(" — try again in {}", wait_text(s)));
    match r.reason {
        reject::NOT_GRANTED => format!(
            "\"{host}\" does not let this device connect without asking: its unattended access \
             for this device is off, paused, expired or was never given. Knock instead, or ask \
             the owner."
        ),
        reject::LOCKED_OUT => format!(
            "Too many wrong passwords: \"{host}\" is not taking any for this device now{}.",
            wait(r.retry_after_s).unwrap_or_default()
        ),
        reject::HARD_LOCKED => format!(
            "Locked until the owner unlocks it at \"{host}\" — or from another of your devices."
        ),
        reject::UA_BUSY => {
            format!("\"{host}\" is busy with other requests right now; try again in a minute.")
        }
        reject::UNSUPPORTED_SUITE => format!(
            "\"{host}\" does not take this build's password method for this device, so the \
             password was not sent. Tornect never tries another method: update Tornect on both \
             computers, or have the owner set this device's access up again."
        ),
        reject::NOT_YET_ACTIVE => format!(
            "\"{host}\" is not accepting this device yet{}: either its access is new and still \
             waiting, or \"{host}\"'s clock was set back.",
            wait(r.next_open_in_s).unwrap_or_default()
        ),
        reject::SUSPENDED if r.cause == Some(cause::SUSPENDED_ADMIN) => format!(
            "Suspended at \"{host}\" until the owner resumes it there — or from another of your \
             devices."
        ),
        reject::SUSPENDED => {
            format!("Suspended at \"{host}\" until the owner resumes it there.")
        }
        reject::AUTH_FAILED => format!("Wrong password for \"{host}\"."),
        reject::OUTSIDE_SCHEDULE => format!(
            "Outside the hours \"{host}\" allows for this device{}.",
            r.next_open_in_s
                .map(|s| format!(
                    " — the next window opens in {} (the host's schedule, in its own time)",
                    wait_text(s)
                ))
                .unwrap_or_default()
        ),
        reject::BLOCKED_BY_LOCAL_USER => format!(
            "Someone at \"{host}\" blocked this connection; unattended access for this device is \
             suspended there until the owner resumes it."
        ),
        reject::HOST_NOT_READY => match r.cause {
            Some(cause::CAPTURE_PERMISSION) => {
                format!("\"{host}\" cannot share its screen now: it has no permission to.")
            }
            Some(cause::INPUT_PERMISSION) => {
                format!("\"{host}\" cannot take control now: it has no permission for input.")
            }
            Some(cause::OTHER_USER_ACTIVE) => {
                format!("Someone else is signed in at \"{host}\".")
            }
            _ => format!("\"{host}\" is offline, asleep or locked."),
        },
        reject::ALREADY_CONNECTED => {
            format!("This device already has a session with \"{host}\".")
        }
        reject::SESSION_ACTIVE => {
            format!("\"{host}\" is already in another remote session.")
        }
        reject::TRANSPORT_UNAVAILABLE => format!(
            "\"{host}\"'s settings forbid the connection this device's access needs (Tor only)."
        ),
        reject::LOCAL_USER_PRESENT => format!(
            "Someone is using \"{host}\" now, and this device's access starts only when nobody is."
        ),
        reject::COOLDOWN => format!(
            "\"{host}\" needs a pause after the last long session{}.",
            wait(r.retry_after_s).unwrap_or_default()
        ),
        reject::PREEMPTED => {
            "A newer request from this device replaced this one; nothing is known about the \
             password."
                .to_owned()
        }
        reject::DENIED => format!("The person at \"{host}\" said no."),
        reject::POPUP_TIMEOUT => format!("Nobody answered at \"{host}\" in time."),
        reject::BUSY => format!("\"{host}\" is busy; try again later."),
        other => format!("\"{host}\" refused (code 0x{other:04x})."),
    }
}

/// How an attempt that got no session ended: its words and what it means for a
/// remembered password (a dial that never reached the host is [`unreachable()`]).
#[must_use]
pub fn ended(err: &HandshakeError, host: &str) -> Ended {
    let plain = |attempt, text: String, reason: &str| Ended {
        attempt,
        text,
        reason: reason.to_owned(),
        blocks: false,
        unreachable: false,
    };
    match err {
        HandshakeError::PasswordRefused => plain(
            Attempt::PasswordRefused,
            format!(
                "Wrong password for \"{host}\" (or its password for this device was changed). \
                 Nothing else was tried."
            ),
            "password_refused",
        ),
        HandshakeError::SessionRejected { reject: r } => plain(
            if r.reason == reject::AUTH_FAILED {
                Attempt::PasswordRefused
            } else {
                Attempt::Inconclusive
            },
            reject_text(r, host),
            &reject::name(r.reason).to_ascii_lowercase(),
        ),
        HandshakeError::ServerKeyChanged => Ended {
            attempt: Attempt::Inconclusive,
            text: format!(
                "\"{host}\"'s unattended setup was re-created since you last connected — if that \
                 wasn't you, revoke devices there. The password was not sent."
            ),
            reason: "setup_changed".to_owned(),
            blocks: true,
            unreachable: false,
        },
        // This side refused the host's answer (C4): the remembered password goes, not
        // as stale.
        HandshakeError::AnswerRefused { code, what }
            if *code == codes::E_BAD_STATE && what.contains("above the request") =>
        {
            plain(
                Attempt::AnswerRefused,
                format!(
                    "\"{host}\" answered with more access than this device asked for, which it must \
                 never do; the connection was closed."
                ),
                "above_the_request",
            )
        }
        HandshakeError::AnswerRefused { .. } => plain(
            Attempt::AnswerRefused,
            format!("The connection to \"{host}\" ended: {err}."),
            "error",
        ),
        // A host that no longer trusts this device answers its request as it
        // answers a stranger's: `E_BAD_STATE` (it expected a pairing).
        HandshakeError::PairingLost
        | HandshakeError::PeerError {
            code: codes::E_BAD_STATE,
            ..
        } => plain(
            Attempt::Inconclusive,
            format!("\"{host}\" may no longer know this device: Knock to pair again."),
            "pairing_lost",
        ),
        HandshakeError::Timeout(_)
        | HandshakeError::Closed
        | HandshakeError::Io(_)
        | HandshakeError::Frame(_)
        | HandshakeError::PeerBye { .. } => plain(
            Attempt::Inconclusive,
            format!(
                "The connection to \"{host}\" broke off before an answer; nothing is known about \
                 the password. Try again when you want to."
            ),
            "connection_lost",
        ),
        other => plain(
            Attempt::Inconclusive,
            format!("The connection to \"{host}\" ended: {other}."),
            "error",
        ),
    }
}

/// The words for a dial that never reached the host: the password was not tried.
#[must_use]
pub fn unreachable(host: &str) -> Ended {
    Ended {
        attempt: Attempt::Inconclusive,
        text: format!(
            "Couldn't reach \"{host}\": it may be off or offline, or Tor may be slow. The \
             password was not tried."
        ),
        reason: "unreachable".to_owned(),
        blocks: false,
        unreachable: true,
    }
}

/// "3 failed attempts since your last login" from a signed accept's
/// `fail_summary`; nothing when there were none.
#[must_use]
pub fn fail_summary_text(summary: Option<messages::FailSummary>) -> Option<String> {
    match summary.map(|s| s.since_success) {
        None | Some(0) => None,
        Some(1) => Some("1 failed attempt since your last login".to_owned()),
        Some(n) => Some(format!("{n} failed attempts since your last login")),
    }
}

/// The badge of an unattended session, from the signed accept: "Unattended ·
/// Control", "Unattended · View", "Unattended · Control · administrator".
#[must_use]
pub fn badge(control: bool, administrator: bool) -> &'static str {
    match (control, administrator) {
        (true, true) => "Unattended · Control · administrator",
        (true, false) => "Unattended · Control",
        (false, _) => "Unattended · View",
    }
}

/// What the client's `sessions.log` line of one unattended attempt says (§B.8.13,
/// B.8.10): the host's pinned device key and label, the outcome, and for a session
/// its id, mode and level; never a password, a token or an address.
#[derive(Debug, Clone)]
pub enum Logged<'a> {
    /// A session started.
    Session {
        /// Its id.
        id: &'a str,
        /// The signed mode.
        control: bool,
        /// The signed level.
        administrator: bool,
    },
    /// An admin command was answered.
    Admin {
        /// Its name.
        op: &'static str,
        /// Whether the host ran it.
        ok: bool,
    },
    /// No session: the outcome's name ([`Ended::reason`]).
    Ended(&'a str),
}

/// Append the client's line for one unattended attempt at `known` (the pin).
pub fn log_attempt(paths: &Paths, known: &KnownHost, logged: &Logged<'_>) {
    let mut record = SessionRecord::now(SessionEvent::UnattendedConnect)
        .unattended(true)
        .peer(
            DeviceId::from_bytes(known.host_device_pk),
            known.label.clone(),
        );
    record = match logged {
        Logged::Session {
            id,
            control,
            administrator,
        } => {
            let r = record
                .session(*id)
                .mode(if *control {
                    SessionMode::Control
                } else {
                    SessionMode::ViewOnly
                })
                .reason("accepted");
            if *administrator {
                r.elevation(tornect_core::levels::Elevation::Admin)
            } else {
                r
            }
        }
        Logged::Admin { op, ok } => record.op(*op).ok(*ok).reason("admin"),
        Logged::Ended(reason) => record.reason(*reason),
    };
    if let Err(e) = SessionLog::new(paths.sessions_log()).append(&record) {
        tracing::warn!(error = %e, "the unattended connect was not logged");
    }
}

/// The delete that comes first (C2 step 1, C4), before `hosts.toml` is read; a refusal of
/// the keychain is said in the log (the record keeps `remember`, C7).
fn delete_first(saved: &SavedPasswords, host: &TornectId) -> Deleted {
    let gone = saved.delete_first(host);
    if gone == Deleted::Refused {
        tracing::warn!("the keychain refused to delete the remembered password");
    }
    gone
}

/// C6, when the prompt opens and before a command-line dial: a record that says both that
/// the host's last answer reached and that a password is remembered has its entry deleted
/// first; `hosts.toml` saved when it changed. `None` when nothing was to be deleted.
pub fn belt(
    paths: &Paths,
    saved: &SavedPasswords,
    host: &TornectId,
) -> anyhow::Result<Option<Deleted>> {
    let path = paths.hosts_file();
    let one = hosts_lock(&path);
    one.held()?;
    let mut file = HostsFile::load(&path)?;
    let done = saved.belt(&mut file, host);
    match done {
        Some(Deleted::Refused) => {
            tracing::warn!("the keychain refused to delete the remembered password");
        }
        Some(Deleted::Entry | Deleted::Nothing) => file.save(&path)?,
        None => {}
    }
    Ok(done)
}

/// Settle one session attempt at `host` (decision M1-67): the host's verified answer
/// alone decides (C1). One that reaches administrator access, leaves `grant_reach` out or
/// was refused deletes the remembered password first, before `hosts.toml` is read, and
/// keeps nothing (C2, C4); an accept of 0 keeps a typed password when Remember was ticked
/// (C3); a refused password is stale and deleted when it was the remembered one; then
/// `hosts.toml` is saved when it changed. An error says that `hosts.toml` could not be read
/// or saved, or that the keychain did not take the password.
pub fn settle(
    paths: &Paths,
    saved: &SavedPasswords,
    host: &TornectId,
    attempt: Attempt,
    request: &Request,
) -> anyhow::Result<Settled> {
    let path = paths.hosts_file();
    let one = hosts_lock(&path);
    let first = attempt.deletes_first().then(|| delete_first(saved, host));
    one.held()?;
    let mut file = HostsFile::load(&path)?;
    let had = file.get(host).is_some_and(|r| r.remember);
    // A refusal says something only of the password that was sent: a typed one that is
    // not the remembered one leaves the remembered one as it is (I-9).
    let attempt = match attempt {
        Attempt::PasswordRefused
            if had
                && !matches!(
                    saved.recall(&file, host),
                    Ok(Some(kept)) if *kept == *request.password
                ) =>
        {
            Attempt::Inconclusive
        }
        other => other,
    };
    let keep = request.remember.then_some(request.password.as_str());
    let settled = saved.settle(&mut file, host, attempt, first, keep)?;
    if settled.changed
        && let Err(e) = file.save(&path)
    {
        // An entry written now whose flag never reached the file would be used and
        // deleted by nothing (F4-5): it goes again, and the failure is reported as before.
        if settled.remembered
            && !had
            && let Err(gone) = saved.erase(host)
        {
            tracing::warn!(error = %gone, "the password just written could not be deleted");
        }
        return Err(e.into());
    }
    Ok(settled)
}

/// The attempt a verified unattended `SESSION_ACCEPT` settles (C1): its signed level and
/// the `grant_reach` decoded from it, never a value of the caller's (C11, VF-14).
#[must_use]
pub fn accepted(accept: &messages::SessionAccept) -> Attempt {
    Attempt::Accepted {
        elevation: accept.elevation(),
        grant_reach: accept.grant_reach(),
    }
}

/// Settle the verified `ADMIN_RESULT` `answer` at `host` by the `grant_reach` decoded from
/// it (C11, VF-14). It takes no password, so none is ever kept after an admin command
/// (DA-15): an answer that reaches deletes the remembered password first, as for an
/// accept (C2); at 0 a remembered one stays (C3).
pub fn settle_admin(
    paths: &Paths,
    saved: &SavedPasswords,
    host: &TornectId,
    answer: &tornect_signal::fsm::client::AdminAnswer,
) -> anyhow::Result<Settled> {
    let grant_reach = answer.grant_reach;
    let path = paths.hosts_file();
    let one = hosts_lock(&path);
    let first = Attempt::reaches(tornect_core::levels::Elevation::None, grant_reach)
        .then(|| delete_first(saved, host));
    one.held()?;
    let mut file = HostsFile::load(&path)?;
    let settled = saved.settle_admin(&mut file, host, grant_reach, first);
    if settled.changed {
        file.save(&path)?;
    }
    Ok(settled)
}

/// What a verified unattended `SESSION_ACCEPT` left at a host (decision M1-67, C1).
pub struct AfterAccept {
    /// What [`settle`] did, or why it failed.
    pub settled: anyhow::Result<Settled>,
    /// The answer deleted the remembered password before anything else (C2): a failed
    /// settle then failed to update `hosts.toml`, not to remember.
    pub deleted_first: bool,
    /// The notes after the answer.
    pub notes: Vec<String>,
}

/// The settle and the notes after the verified unattended `accept` of `request` at
/// `host`, named `named` (quoted) in the notes: the command line's and the window's one
/// path once a session started (decision M1-67, C1), by the attempt decoded from the
/// signed frame alone. `withheld`: the level was asked for and not given.
pub fn after_accept(
    paths: &Paths,
    saved: &SavedPasswords,
    host: &TornectId,
    accept: &messages::SessionAccept,
    request: &Request,
    named: &str,
    withheld: bool,
) -> AfterAccept {
    let attempt = accepted(accept);
    let settled = settle(paths, saved, host, attempt, request);
    let answered = Answered::Session {
        elevation: accept.elevation(),
        grant_reach: accept.grant_reach(),
        asked_control: !request.view_only,
        given_control: matches!(
            tornect_signal::consent::mode_from_code(accept.mode()),
            Some(SessionMode::Control)
        ),
        withheld,
    };
    let notes = notes(
        named,
        saved.keychain().unwrap_or("the keychain"),
        answered,
        request.remember,
        settled.as_ref().ok(),
    );
    AfterAccept {
        settled,
        deleted_first: attempt.deletes_first(),
        notes,
    }
}

/// The admin settle and the notes after the verified `ADMIN_RESULT` `answer` at `host`,
/// named `named` (quoted) in the notes: the command line's and the window's one path once
/// an admin command was answered (decision M1-67, C11). An error says that `hosts.toml`
/// could not be updated.
pub fn after_admin(
    paths: &Paths,
    saved: &SavedPasswords,
    host: &TornectId,
    answer: &tornect_signal::fsm::client::AdminAnswer,
    named: &str,
) -> anyhow::Result<Vec<String>> {
    let settled = settle_admin(paths, saved, host, answer)?;
    Ok(notes(
        named,
        saved.keychain().unwrap_or("the keychain"),
        Answered::Admin {
            grant_reach: answer.grant_reach,
        },
        false,
        Some(&settled),
    ))
}

/// What one verified unattended answer was, for the notes after it (decision M1-67).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answered {
    /// A `SESSION_ACCEPT`.
    Session {
        /// The level it signed.
        elevation: tornect_core::levels::Elevation,
        /// Its `grant_reach`, if it carried one.
        grant_reach: Option<u8>,
        /// Control was asked for.
        asked_control: bool,
        /// The signed mode is control.
        given_control: bool,
        /// The administrator level was asked for and not given.
        withheld: bool,
    },
    /// An `ADMIN_RESULT`.
    Admin {
        /// Its `grant_reach`, if it carried one.
        grant_reach: Option<u8>,
    },
    /// A `SESSION_ACCEPT` or `ADMIN_RESULT` this side refused (C4).
    Refused,
}

/// The notes after an answer at `host` (decision M1-67, its client copy), each naming the
/// host as given (quoted by the caller): about the password from the answer, whether
/// Remember was ticked and what [`settle`] did (`None`: it failed, and its error says why);
/// about the session whatever the settle did. `keychain` is the keychain's name.
#[must_use]
pub fn notes(
    host: &str,
    keychain: &str,
    answered: Answered,
    ticked: bool,
    settled: Option<&Settled>,
) -> Vec<String> {
    use tornect_core::levels::Elevation;
    use tornect_core::unattended::credentials::note;
    let mut out = Vec::new();
    if let Some(settled) = settled {
        if settled.delete_failed {
            out.push(note::failed_delete(host, keychain));
        }
        let (reach, grant_reach, control) = match answered {
            Answered::Session {
                elevation,
                grant_reach,
                given_control,
                ..
            } => (
                Attempt::reaches(elevation, grant_reach),
                grant_reach,
                given_control,
            ),
            Answered::Admin { grant_reach } => (
                Attempt::reaches(Elevation::None, grant_reach),
                grant_reach,
                false,
            ),
            Answered::Refused => (true, None, false),
        };
        if answered == Answered::Refused {
            if settled.forgot {
                out.push(note::refused_answer(host));
            }
        } else if reach {
            match grant_reach {
                None if settled.forgot || ticked => {
                    out.push(note::absent_key(host, settled.forgot));
                }
                Some(_) if settled.forgot => out.push(note::deleted_at_reach(host, control)),
                Some(2) if ticked => out.push(note::answer_2(host)),
                Some(_) if ticked => out.push(note::answer_1(host)),
                None | Some(_) => {}
            }
        }
    }
    if let Answered::Session {
        asked_control: true,
        given_control: false,
        grant_reach: Some(1 | 2),
        ..
    } = answered
    {
        out.push(note::view_only(host));
    }
    if let Answered::Session { withheld: true, .. } = answered {
        out.push(note::level_not_given(host));
    }
    out
}

/// The notes after an attempt that got no session: only a refused answer has any (C4).
#[must_use]
pub fn refused_notes(
    host: &str,
    keychain: &str,
    attempt: Attempt,
    settled: &Settled,
) -> Vec<String> {
    if attempt == Attempt::AnswerRefused {
        notes(host, keychain, Answered::Refused, false, Some(settled))
    } else {
        Vec::new()
    }
}

/// Record the signed mode of an accepted session at `host` (the host card
/// offers the control grants' admin actions from it).
pub fn note_mode(paths: &Paths, host: &TornectId, control: bool) -> anyhow::Result<()> {
    let path = paths.hosts_file();
    let one = hosts_lock(&path);
    one.held()?;
    let mut file = HostsFile::load(&path)?;
    let record = file.entry(host);
    if record.control != control {
        record.control = control;
        file.save(&path)?;
    }
    Ok(())
}

/// The person read that `host`'s unattended setup was re-created (A16): its
/// pin goes, and the next accept pins the new key.
pub fn renew_pin(paths: &Paths, host: &TornectId) -> anyhow::Result<()> {
    let path = paths.hosts_file();
    let one = hosts_lock(&path);
    one.held()?;
    let mut file = HostsFile::load(&path)?;
    file.clear_pin(host);
    file.save(&path)?;
    Ok(())
}

/// The admin commands of the host card (§B.8.10) and their names in the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminAction {
    /// Revoke this device's own grant (every grant may).
    RevokeThisDevice,
    /// End this device's live session at the host (every grant may).
    EndSession,
    /// Turn unattended access off at the host (*My machines* Control grants).
    TurnOff,
    /// Reset another device's lockout (*My machines* Control grants).
    Unlock,
}

impl AdminAction {
    /// The host card's button.
    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            Self::RevokeThisDevice => "Revoke this device",
            Self::EndSession => "End the session there",
            Self::TurnOff => "Turn unattended off there",
            Self::Unlock => "Unlock another device there",
        }
    }

    /// The wire op.
    #[must_use]
    pub fn op(self) -> u8 {
        match self {
            Self::RevokeThisDevice => messages::admin_op::REVOKE,
            Self::EndSession => messages::admin_op::END_SESSION,
            Self::TurnOff => messages::admin_op::MASTER_OFF,
            Self::Unlock => messages::admin_op::UNLOCK,
        }
    }

    /// Its name in the log.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::RevokeThisDevice => "revoke",
            Self::EndSession => "end_session",
            Self::TurnOff => "master_off",
            Self::Unlock => "unlock",
        }
    }

    /// The confirmation, naming the host.
    #[must_use]
    pub fn confirmation(self, host: &str) -> String {
        match self {
            Self::RevokeThisDevice => format!(
                "Revoke this device at \"{host}\"? It will no longer connect there without \
                 asking; only the owner at \"{host}\" can give that back."
            ),
            Self::EndSession => {
                format!("End this device's session at \"{host}\"?")
            }
            Self::TurnOff => format!(
                "Turn unattended access off at \"{host}\"? No device connects there without \
                 asking until the owner turns it on again at \"{host}\"."
            ),
            Self::Unlock => format!(
                "Unlock your other device at \"{host}\"? Its wrong-password lock is reset there, \
                 and a suspension set from another of your devices is lifted."
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rejected(reason: u16) -> SessionReject {
        SessionReject {
            reason,
            cause: None,
            retry_after_s: None,
            next_open_in_s: None,
            detail: None,
        }
    }

    /// Every reject code of §B.8.4.6 has its own plain words naming the host,
    /// and only `AUTH_FAILED` among them marks a remembered password stale.
    #[test]
    fn every_reject_code_has_plain_words() {
        let codes = [
            reject::NOT_GRANTED,
            reject::LOCKED_OUT,
            reject::HARD_LOCKED,
            reject::UA_BUSY,
            reject::UNSUPPORTED_SUITE,
            reject::NOT_YET_ACTIVE,
            reject::SUSPENDED,
            reject::AUTH_FAILED,
            reject::OUTSIDE_SCHEDULE,
            reject::BLOCKED_BY_LOCAL_USER,
            reject::HOST_NOT_READY,
            reject::ALREADY_CONNECTED,
            reject::SESSION_ACTIVE,
            reject::TRANSPORT_UNAVAILABLE,
            reject::LOCAL_USER_PRESENT,
            reject::COOLDOWN,
            reject::PREEMPTED,
        ];
        let mut seen = std::collections::HashSet::new();
        for code in codes {
            let err = HandshakeError::SessionRejected {
                reject: Box::new(rejected(code)),
            };
            let e = ended(&err, "Desk");
            assert!(!e.text.contains("code 0x"), "{code:#x}: {}", e.text);
            assert!(seen.insert(e.text.clone()), "{code:#x} shares its words");
            assert_eq!(
                e.attempt == Attempt::PasswordRefused,
                code == reject::AUTH_FAILED,
                "{code:#x}"
            );
            if code != reject::PREEMPTED {
                assert!(e.text.contains("\"Desk\""), "{code:#x}: {}", e.text);
            }
        }
        let with = |reason, cause, retry, next| SessionReject {
            reason,
            cause,
            retry_after_s: retry,
            next_open_in_s: next,
            detail: None,
        };
        assert_eq!(
            reject_text(&with(reject::HARD_LOCKED, None, None, None), "Desk"),
            "Locked until the owner unlocks it at \"Desk\" — or from another of your devices."
        );
        assert!(
            reject_text(
                &with(reject::SUSPENDED, Some(cause::SUSPENDED_ADMIN), None, None),
                "Desk"
            )
            .ends_with("— or from another of your devices.")
        );
        assert!(
            !reject_text(
                &with(reject::SUSPENDED, Some(cause::SUSPENDED_LOCAL), None, None),
                "Desk"
            )
            .contains("another of your devices")
        );
        assert!(
            reject_text(&with(reject::LOCKED_OUT, None, Some(125), None), "Desk")
                .contains("try again in 3 min")
        );
        assert!(
            reject_text(
                &with(reject::NOT_YET_ACTIVE, None, None, Some(7200)),
                "Desk"
            )
            .contains("clock was set back")
        );
        assert!(
            reject_text(
                &with(reject::HOST_NOT_READY, Some(cause::LOCKED), None, None),
                "Desk"
            )
            .contains("offline, asleep or locked")
        );
        assert!(
            reject_text(
                &with(reject::OUTSIDE_SCHEDULE, None, None, Some(3600)),
                "Desk"
            )
            .contains("next window opens in 1 h")
        );
        assert_eq!(wait_text(90_000), "24 h", "capped at a day");
    }

    /// The words keep "couldn't reach" apart from "wrong password", and only a
    /// refused password is stale; a changed setup blocks until confirmed.
    #[test]
    fn unreachable_wrong_password_and_a_broken_stream_read_differently() {
        let wrong = ended(&HandshakeError::PasswordRefused, "Desk");
        assert_eq!(wrong.attempt, Attempt::PasswordRefused);
        assert!(wrong.text.starts_with("Wrong password"));
        let away = unreachable("Desk");
        assert!(away.unreachable && away.text.starts_with("Couldn't reach"));
        assert_eq!(away.attempt, Attempt::Inconclusive);
        for err in [
            HandshakeError::Closed,
            HandshakeError::Timeout("SESSION_ACCEPT"),
            HandshakeError::PeerBye {
                reason: messages::bye::USER,
                detail: None,
            },
        ] {
            let e = ended(&err, "Desk");
            assert_eq!(e.attempt, Attempt::Inconclusive, "{err}");
            assert!(e.text.contains("nothing is known about the password"));
        }
        let lost = ended(
            &HandshakeError::PeerError {
                code: codes::E_BAD_STATE,
                detail: None,
            },
            "Desk",
        );
        assert_eq!(lost.reason, "pairing_lost");
        assert!(lost.text.contains("Knock to pair again"));
        let changed = ended(&HandshakeError::ServerKeyChanged, "Desk");
        assert!(changed.blocks);
        assert!(changed.text.contains("re-created since you last connected"));
        let above = ended(
            &HandshakeError::AnswerRefused {
                code: codes::E_BAD_STATE,
                what: "level above the request",
            },
            "Desk",
        );
        assert_eq!(above.reason, "above_the_request");
    }

    #[test]
    fn the_badge_and_the_fail_summary() {
        assert_eq!(badge(true, false), "Unattended · Control");
        assert_eq!(badge(false, false), "Unattended · View");
        assert_eq!(badge(true, true), "Unattended · Control · administrator");
        assert_eq!(badge(false, true), "Unattended · View");
        let fs = |n, at| {
            Some(messages::FailSummary {
                since_success: n,
                last_fail_at: at,
            })
        };
        assert_eq!(fail_summary_text(None), None);
        assert_eq!(fail_summary_text(fs(0, None)), None);
        assert_eq!(
            fail_summary_text(fs(1, Some(5))).as_deref(),
            Some("1 failed attempt since your last login")
        );
        assert_eq!(
            fail_summary_text(fs(3, Some(5))).as_deref(),
            Some("3 failed attempts since your last login")
        );
    }

    /// A password is taken from the terminal's prompt only: one on the command
    /// line or in the environment is refused, with the reason.
    #[test]
    fn a_password_on_the_command_line_or_in_the_environment_is_refused() {
        use std::ffi::OsString;
        let none: Vec<(OsString, OsString)> = Vec::new();
        let err = refuse_password_sources(true, none.clone()).unwrap_err();
        assert!(
            err.to_string()
                .contains("never takes a password on the command line")
        );
        assert!(refuse_password_sources(false, none).is_ok());
        for name in [
            "TORNECT_PASSWORD",
            "TORNECT_UNATTENDED_PASSWORD",
            "tornect_password",
        ] {
            let vars = vec![(OsString::from(name), OsString::from("secret"))];
            let err = refuse_password_sources(false, vars)
                .unwrap_err()
                .to_string();
            assert!(err.contains("from the environment"), "{name}: {err}");
            assert!(!err.contains("secret"), "the value is never repeated");
        }
        let unrelated = vec![
            (OsString::from("TORNECT_HOME"), OsString::from("/x")),
            (OsString::from("PASSWORD_STORE_DIR"), OsString::from("/y")),
        ];
        assert!(refuse_password_sources(false, unrelated).is_ok());
    }

    /// The client's `sessions.log` line: the host's pinned device and label, the
    /// outcome, the level only for an administrator session; no address.
    #[test]
    fn the_clients_line_says_what_the_log_keeps_and_no_more() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        paths.ensure().unwrap();
        let known = KnownHost {
            label: "Desk".to_owned(),
            host_device_pk: [7; 32],
            paired_at: 1,
            last_seen: 1,
        };
        log_attempt(
            &paths,
            &known,
            &Logged::Session {
                id: "0123456789abcdef",
                control: true,
                administrator: true,
            },
        );
        log_attempt(&paths, &known, &Logged::Ended("password_refused"));
        log_attempt(
            &paths,
            &known,
            &Logged::Admin {
                op: "revoke",
                ok: true,
            },
        );
        let log = std::fs::read_to_string(paths.sessions_log()).unwrap();
        let lines: Vec<&str> = log.lines().collect();
        assert_eq!(lines.len(), 3, "{log}");
        for line in &lines {
            assert!(line.contains(r#""event":"unattended_connect""#), "{line}");
            assert!(line.contains(r#""peer_name":"Desk""#), "{line}");
            assert!(line.contains(r#""unattended":true"#), "{line}");
        }
        assert!(lines[0].contains(r#""elevation":"admin""#));
        assert!(lines[0].contains(r#""session_id":"0123456789abcdef""#));
        assert!(lines[0].contains(r#""mode":"control""#));
        assert!(lines[1].contains(r#""reason":"password_refused""#));
        assert!(!lines[1].contains("elevation"));
        assert!(lines[2].contains(r#""op":"revoke""#) && lines[2].contains(r#""ok":true"#));
    }

    /// A home with a test keychain (the `PasswordVault` seam).
    fn with_vault() -> (
        tempfile::TempDir,
        Paths,
        std::sync::Arc<tornect_core::unattended::credentials::MemoryVault>,
        SavedPasswords,
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        paths.ensure().unwrap();
        let vault = std::sync::Arc::new(tornect_core::unattended::credentials::MemoryVault::new());
        let saved = SavedPasswords::new(Some(vault.clone()), [1; 32]);
        (tmp, paths, vault, saved)
    }

    fn host(n: u8) -> TornectId {
        TornectId::from_bytes([n; 32])
    }

    /// §B.8.9.1: a second holder of the lock beside `hosts.toml` (another Tornect,
    /// as a second open of the file stands for here) waits while the first holds
    /// it, gives up with the lock's own error when the wait runs out, and gets the
    /// lock once the first lets go; the lock file is this account's only.
    #[test]
    fn a_second_holder_waits_for_the_hosts_file_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let hosts = tmp.path().join("state").join("hosts.toml");
        let first = lock_file(&hosts, HOSTS_LOCK_WAIT).unwrap();
        assert_eq!(
            lock_file(&hosts, Duration::from_millis(120)).unwrap_err(),
            HOSTS_LOCK_HELD
        );
        let waiter = std::thread::spawn({
            let hosts = hosts.clone();
            move || lock_file(&hosts, HOSTS_LOCK_WAIT).map(drop)
        });
        std::thread::sleep(Duration::from_millis(300));
        assert!(
            !waiter.is_finished(),
            "it waits while the first holds the lock"
        );
        drop(first);
        assert_eq!(waiter.join().unwrap(), Ok(()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let lock = tmp.path().join("state").join("hosts.toml.lock");
            let mode = std::fs::metadata(lock).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert_eq!(
            HOSTS_LOCK_HELD,
            "another Tornect held the lock beside hosts.toml for more than 10 s; nothing was saved"
        );
    }

    /// The lock beside `hosts.toml` cannot be taken (its path is a directory here):
    /// an operation that saves fails with the lock's error, and `hosts.toml` is
    /// left as it was; there is no way around the lock.
    #[test]
    fn a_lock_that_cannot_be_taken_fails_the_save() {
        let (_tmp, paths, _vault, saved) = with_vault();
        let desk = host(4);
        note_mode(&paths, &desk, true).unwrap();
        let before = std::fs::read(paths.hosts_file()).unwrap();
        let lock = paths.state_dir.join("hosts.toml.lock");
        std::fs::remove_file(&lock).unwrap();
        std::fs::create_dir(&lock).unwrap();
        let refused = note_mode(&paths, &desk, false).unwrap_err().to_string();
        assert!(
            refused.starts_with("the lock beside hosts.toml could not be taken")
                && refused.ends_with("nothing was saved"),
            "{refused}"
        );
        assert!(renew_pin(&paths, &desk).is_err());
        assert!(belt(&paths, &saved, &desk).is_err());
        assert_eq!(std::fs::read(paths.hosts_file()).unwrap(), before);
        // Every other operation that saves `hosts.toml` holds the lock too: each one
        // that went on without it is named here.
        let mut went_on = Vec::new();
        let fresh = host(6);
        let settled = settle(&paths, &saved, &fresh, ACCEPTED, &typed("pw", true));
        if settled.is_ok() || saved.erase(&fresh).unwrap() {
            went_on.push("settle");
        }
        if settle_admin(&paths, &saved, &fresh, &admin_answer(Some(0))).is_ok() {
            went_on.push("settle_admin");
        }
        if std::fs::read(paths.hosts_file()).unwrap() != before {
            went_on.push("a settle wrote hosts.toml");
        }
        // A remembered password whose keychain entry is gone, and one still there,
        // made while the lock can be taken.
        std::fs::remove_dir(&lock).unwrap();
        let (vanished, kept) = (host(7), host(8));
        for h in [vanished, kept] {
            assert!(
                settle(&paths, &saved, &h, ACCEPTED, &typed("pw", true))
                    .unwrap()
                    .remembered
            );
        }
        assert!(saved.erase(&vanished).unwrap());
        let before = std::fs::read(paths.hosts_file()).unwrap();
        std::fs::remove_file(&lock).unwrap();
        std::fs::create_dir(&lock).unwrap();
        if recall_for_use(&paths, &saved, &vanished).is_ok() {
            went_on.push("recall_for_use");
        }
        if !matches!(forget(&paths, &saved, &kept), Err(Kept::Record(_))) {
            went_on.push("forget");
        }
        if forget_all(&paths, &saved).is_ok() {
            went_on.push("forget_all");
        }
        if std::fs::read(paths.hosts_file()).unwrap() != before {
            went_on.push("a flag cleared or a record removed in hosts.toml");
        }
        assert!(went_on.is_empty(), "without the lock: {went_on:?}");
        assert!(!saved.erase(&kept).unwrap(), "Forget deleted the password");
    }

    /// A pin check whose lock cannot be taken answers `Mismatch`, so no proof is
    /// sent, even for a host with no pin yet, whose answer would otherwise be "no
    /// pin": a lock not taken never trusts a new host key. The pin's record then
    /// writes nothing.
    #[test]
    fn a_pin_check_without_the_lock_is_a_mismatch() {
        let (_tmp, paths, _vault, _saved) = with_vault();
        let pin = HostsPin::new(&paths);
        let desk = host(5);
        assert_eq!(pin.check(&desk, &[9; 32]), PinCheck::NoPin);
        let lock = paths.state_dir.join("hosts.toml.lock");
        std::fs::remove_file(&lock).unwrap();
        std::fs::create_dir(&lock).unwrap();
        assert_eq!(pin.check(&desk, &[9; 32]), PinCheck::Mismatch);
        pin.record(&desk, &[9; 32]);
        assert!(!paths.hosts_file().exists(), "nothing written");
    }

    fn typed(password: &str, remember: bool) -> Request {
        Request {
            password: Zeroizing::new(password.to_owned()),
            view_only: false,
            administrator: false,
            remember,
        }
    }

    const ACCEPTED: Attempt = Attempt::Accepted {
        elevation: tornect_core::levels::Elevation::None,
        grant_reach: Some(0),
    };

    /// F4-5: when `hosts.toml` cannot be saved after the password went into the
    /// keychain, the entry goes again and the failure is reported as before.
    #[test]
    fn a_failed_save_leaves_no_password_behind() {
        use tornect_core::unattended::credentials::PasswordVault as _;
        let (_tmp, paths, vault, saved) = with_vault();
        let h = host(3);
        // The atomic save writes `hosts.toml.tmp` first: a directory there fails it.
        let tmp_file = paths.hosts_file().with_extension("toml.tmp");
        std::fs::create_dir_all(&tmp_file).unwrap();
        assert!(settle(&paths, &saved, &h, ACCEPTED, &typed("pw", true)).is_err());
        assert!(vault.names().is_empty(), "{:?}", vault.names());
        assert!(!record(&paths, &h).remember);
        // Saved once the file can be written: kept, flagged.
        std::fs::remove_dir(&tmp_file).unwrap();
        assert!(
            settle(&paths, &saved, &h, ACCEPTED, &typed("pw", true))
                .unwrap()
                .remembered
        );
        assert_eq!(vault.names().len(), 1);
        assert!(vault.get(&saved.entry(&h)).unwrap().is_some());
    }

    /// F4-L2: Forget deletes the keychain entry before it reads `hosts.toml`, so a
    /// file that cannot be read keeps no password.
    #[test]
    fn forget_deletes_the_password_when_the_file_cannot_be_read() {
        let (_tmp, paths, vault, saved) = with_vault();
        let h = host(4);
        assert!(
            settle(&paths, &saved, &h, ACCEPTED, &typed("pw", true))
                .unwrap()
                .remembered
        );
        std::fs::write(paths.hosts_file(), "not = [valid").unwrap();
        assert!(
            matches!(forget(&paths, &saved, &h), Err(Kept::Record(_))),
            "the file's error is reported, and the password went"
        );
        assert!(vault.names().is_empty(), "{:?}", vault.names());
    }

    /// F4-5: Rotate ID deletes the derived entry of every host of `hosts.toml` and
    /// `known-hosts.toml`, whatever its flag says, and clears the flags.
    #[test]
    fn rotate_id_deletes_every_hosts_password_whatever_its_flag() {
        use tornect_core::unattended::credentials::PasswordVault as _;
        let (_tmp, paths, vault, saved) = with_vault();
        let (flagged, unflagged, paired) = (host(5), host(6), host(7));
        assert!(
            settle(&paths, &saved, &flagged, ACCEPTED, &typed("a", true))
                .unwrap()
                .remembered
        );
        // A record without the flag whose entry is in the keychain (a save that failed
        // before), and a paired host with no record at all.
        note_mode(&paths, &unflagged, true).unwrap();
        vault.put(&saved.entry(&unflagged), "b").unwrap();
        vault.put(&saved.entry(&paired), "c").unwrap();
        let mut known = tornect_core::trusted::KnownHosts::default();
        known.pin(paired, "Desk", [9; 32], 1);
        known
            .save(&tornect_core::trusted::known_hosts_file(&paths))
            .unwrap();
        assert_eq!(forget_all(&paths, &saved).unwrap(), 3);
        assert!(vault.names().is_empty(), "{:?}", vault.names());
        assert!(!record(&paths, &flagged).remember);
        assert_eq!(forget_all(&paths, &saved).unwrap(), 0, "nothing left");
    }

    /// I-9: a flag whose keychain entry is gone (a restart empties the kernel
    /// keyrings) is cleared when the password is needed, and the password is asked
    /// for; a flag with its entry gives the password; without a keychain the flag stays.
    #[test]
    fn a_remembered_password_that_vanished_is_asked_for_again() {
        use tornect_core::unattended::credentials::PasswordVault as _;
        let (_tmp, paths, vault, saved) = with_vault();
        let h = host(8);
        assert!(
            settle(&paths, &saved, &h, ACCEPTED, &typed("pw", true))
                .unwrap()
                .remembered
        );
        assert!(matches!(
            recall_for_use(&paths, &saved, &h).unwrap(),
            Recalled::Password(p) if *p == "pw"
        ));
        let none = SavedPasswords::none([1; 32]);
        assert!(matches!(
            recall_for_use(&paths, &none, &h).unwrap(),
            Recalled::Nothing
        ));
        assert!(record(&paths, &h).remember, "no keychain: the flag stays");
        vault.delete(&saved.entry(&h)).unwrap();
        assert!(matches!(
            recall_for_use(&paths, &saved, &h).unwrap(),
            Recalled::Vanished
        ));
        assert!(!record(&paths, &h).remember, "the flag went");
        assert!(matches!(
            recall_for_use(&paths, &saved, &h).unwrap(),
            Recalled::Nothing
        ));
    }

    /// I-9: a typed password the host refuses leaves the remembered one, its flag and
    /// no stale mark; a refusal of the remembered password itself (typed again or
    /// recalled) deletes it and marks it stale.
    #[test]
    fn only_a_refusal_of_the_remembered_password_deletes_it() {
        let (_tmp, paths, vault, saved) = with_vault();
        let h = host(9);
        assert!(
            settle(&paths, &saved, &h, ACCEPTED, &typed("pw", true))
                .unwrap()
                .remembered
        );
        let refused = Attempt::PasswordRefused;
        assert!(
            settle(&paths, &saved, &h, refused, &typed("typo", false))
                .unwrap()
                .remembered
        );
        let r = record(&paths, &h);
        assert!(r.remember && !r.stale);
        assert_eq!(vault.names().len(), 1);
        assert!(
            !settle(&paths, &saved, &h, refused, &typed("pw", false))
                .unwrap()
                .remembered
        );
        let r = record(&paths, &h);
        assert!(!r.remember && r.stale);
        assert!(vault.names().is_empty());
    }

    /// An accept that says 1.
    const ONE: Attempt = Attempt::Accepted {
        elevation: tornect_core::levels::Elevation::None,
        grant_reach: Some(1),
    };

    /// An accept that leaves `grant_reach` out (an older host).
    const ABSENT: Attempt = Attempt::Accepted {
        elevation: tornect_core::levels::Elevation::None,
        grant_reach: None,
    };

    /// Edit `host`'s record in hosts.toml as another program of the user could.
    fn edit(
        paths: &Paths,
        host: &TornectId,
        change: impl FnOnce(&mut tornect_core::unattended::hosts::HostRecord),
    ) {
        let mut file = HostsFile::load(&paths.hosts_file()).unwrap();
        change(file.entry(host));
        file.save(&paths.hosts_file()).unwrap();
    }

    /// A keychain that notes, at every delete, whether hosts.toml already said `reach`.
    struct Watching {
        inner: tornect_core::unattended::credentials::MemoryVault,
        file: std::path::PathBuf,
        seen: Mutex<Vec<bool>>,
    }

    impl tornect_core::unattended::credentials::PasswordVault for Watching {
        fn describe(&self) -> &'static str {
            "a test keychain"
        }
        fn presence_gated(&self) -> bool {
            false
        }
        fn get(
            &self,
            entry: &tornect_core::unattended::credentials::EntryName,
        ) -> tornect_core::Result<Option<Zeroizing<String>>> {
            self.inner.get(entry)
        }
        fn put(
            &self,
            entry: &tornect_core::unattended::credentials::EntryName,
            password: &str,
        ) -> tornect_core::Result<()> {
            self.inner.put(entry, password)
        }
        fn delete(
            &self,
            entry: &tornect_core::unattended::credentials::EntryName,
        ) -> tornect_core::Result<bool> {
            let reach =
                HostsFile::load(&self.file).is_ok_and(|f| f.hosts.values().any(|r| r.reach));
            self.seen.lock().unwrap().push(reach);
            self.inner.delete(entry)
        }
    }

    /// C2 step 1, C4: an answer that reaches, leaves the key out or was refused deletes the
    /// remembered password first: before hosts.toml is written (the keychain sees the file
    /// still without `reach`), and whether or not the file can be read.
    #[test]
    fn the_delete_comes_before_hosts_toml() {
        use tornect_core::unattended::credentials::PasswordVault as _;
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path());
        paths.ensure().unwrap();
        let vault = std::sync::Arc::new(Watching {
            inner: tornect_core::unattended::credentials::MemoryVault::new(),
            file: paths.hosts_file(),
            seen: Mutex::new(Vec::new()),
        });
        let saved = SavedPasswords::new(Some(vault.clone()), [1; 32]);
        let h = host(11);
        for answer in [ONE, ABSENT, Attempt::AnswerRefused] {
            assert!(
                settle(&paths, &saved, &h, ACCEPTED, &typed("pw", true))
                    .unwrap()
                    .remembered
            );
            vault.seen.lock().unwrap().clear();
            let s = settle(&paths, &saved, &h, answer, &typed("pw", true)).unwrap();
            assert!(s.forgot && !s.remembered, "{answer:?}");
            assert_eq!(vault.inner.names().len(), 0, "{answer:?}");
            assert_eq!(
                vault.seen.lock().unwrap().first(),
                Some(&false),
                "{answer:?}: the delete came after the file was written"
            );
            assert!(record(&paths, &h).reach, "{answer:?}");
        }
        // A file that cannot be read does not stop it.
        std::fs::write(paths.hosts_file(), "not = [valid").unwrap();
        for answer in [ONE, ABSENT, Attempt::AnswerRefused] {
            vault.put(&saved.entry(&h), "pw").unwrap();
            assert!(settle(&paths, &saved, &h, answer, &typed("pw", true)).is_err());
            assert!(vault.inner.names().is_empty(), "{answer:?}");
        }
    }

    /// A verified admin answer that ran its command, with `grant_reach`.
    fn admin_answer(grant_reach: Option<u8>) -> tornect_signal::fsm::client::AdminAnswer {
        tornect_signal::fsm::client::AdminAnswer {
            ok: true,
            detail: None,
            grant_reach,
        }
    }

    /// C1, C11 (VF-14): every settle call site passes the key decoded from the verified
    /// frame, the session's through [`accepted`] and the admin command's through its
    /// answer, never a value of its own. On constructed frames (vectors 4 and 5, and
    /// vector 4 without key 12) and constructed admin answers, the keychain ends as the
    /// decoded key says.
    #[test]
    fn the_settle_call_sites_pass_the_decoded_key() {
        use tornect_core::levels::Elevation;
        use tornect_core::unattended::credentials::PasswordVault as _;
        let decode = |hex: &str| {
            let body = data_encoding::HEXLOWER.decode(hex.as_bytes()).unwrap();
            messages::decode_body::<messages::SessionAccept>(&body).unwrap()
        };
        for (hex, grant_reach, kept) in [
            (
                "a900a400816468323634018219078019043802f4030101582c302a300506032b6570032100705fbac01f5519899f437bc42e40255ae9ab54bff00de3433af7d687d9e71ad50201030004000658207777777777777777777777777777777777777777777777777777777777777777070008f40c00",
                Some(0),
                true,
            ),
            (
                "a900a400816468323634018219078019043802f4030101582c302a300506032b6570032100705fbac01f5519899f437bc42e40255ae9ab54bff00de3433af7d687d9e71ad50201030004000658207777777777777777777777777777777777777777777777777777777777777777070008f40c01",
                Some(1),
                false,
            ),
            (
                "a800a400816468323634018219078019043802f4030101582c302a300506032b6570032100705fbac01f5519899f437bc42e40255ae9ab54bff00de3433af7d687d9e71ad50201030004000658207777777777777777777777777777777777777777777777777777777777777777070008f4",
                None,
                false,
            ),
        ] {
            let attempt = accepted(&decode(hex));
            assert_eq!(
                attempt,
                Attempt::Accepted {
                    elevation: Elevation::None,
                    grant_reach
                }
            );
            let (_tmp, paths, vault, saved) = with_vault();
            let h = host(30);
            let s = settle(&paths, &saved, &h, attempt, &typed("pw", true)).unwrap();
            assert_eq!(s.remembered, kept, "{grant_reach:?}");
            assert_eq!(vault.names().len(), usize::from(kept), "{grant_reach:?}");
        }
        for (grant_reach, kept) in [
            (Some(0), true),
            (Some(1), false),
            (Some(2), false),
            (None, false),
        ] {
            let (_tmp, paths, vault, saved) = with_vault();
            let h = host(31);
            vault.put(&saved.entry(&h), "pw").unwrap();
            edit(&paths, &h, |r| r.remember = true);
            let s = settle_admin(&paths, &saved, &h, &admin_answer(grant_reach)).unwrap();
            assert_eq!(s.remembered, kept, "{grant_reach:?}");
            assert_eq!(vault.names().len(), usize::from(kept), "{grant_reach:?}");
        }
    }

    /// DA-15 (C3): a verified admin answer never keeps a password, and the admin settle
    /// takes none. At 0 a remembered one stays; an answer that reaches or leaves the key out
    /// deletes it first, and the record says so for the prompt.
    #[test]
    fn an_admin_settle_keeps_no_password() {
        use tornect_core::unattended::credentials::PasswordVault as _;
        let (_tmp, paths, vault, saved) = with_vault();
        let h = host(12);
        let s = settle_admin(&paths, &saved, &h, &admin_answer(Some(0))).unwrap();
        assert!(!s.remembered && vault.names().is_empty());
        assert!(
            settle(&paths, &saved, &h, ACCEPTED, &typed("pw", true))
                .unwrap()
                .remembered
        );
        let s = settle_admin(&paths, &saved, &h, &admin_answer(Some(0))).unwrap();
        assert!(s.remembered && !s.forgot);
        assert_eq!(vault.names().len(), 1);
        for reach in [Some(1), Some(2), None] {
            vault.put(&saved.entry(&h), "pw").unwrap();
            edit(&paths, &h, |r| r.remember = true);
            let s = settle_admin(&paths, &saved, &h, &admin_answer(reach)).unwrap();
            assert!(s.forgot && !s.remembered, "{reach:?}");
            assert!(vault.names().is_empty(), "{reach:?}");
            let r = record(&paths, &h);
            assert!(r.reach && !r.remember, "{reach:?}");
            assert_eq!(r.administrator, reach == Some(2), "{reach:?}");
        }
    }

    /// C4: only a refused `SESSION_ACCEPT` or `ADMIN_RESULT` deletes. A refused `HELLO_ACK`
    /// or `AUTH_CHALLENGE` is a violation like any other and stays inconclusive, as a
    /// changed OPAQUE key does, and its settle deletes nothing; a refused answer, F-8
    /// included, keeps its words.
    #[test]
    fn a_refused_hello_ack_is_inconclusive() {
        let hello_ack = HandshakeError::Violation {
            code: codes::E_BAD_SIG,
            what: "signature",
        };
        let auth_challenge = HandshakeError::Violation {
            code: codes::E_BAD_LEN,
            what: "suite",
        };
        for err in [
            &hello_ack,
            &auth_challenge,
            &HandshakeError::ServerKeyChanged,
        ] {
            assert_eq!(ended(err, "Desk").attempt, Attempt::Inconclusive, "{err}");
        }
        let refused = HandshakeError::AnswerRefused {
            code: codes::E_BAD_SIG,
            what: "signature",
        };
        let e = ended(&refused, "Desk");
        assert_eq!(e.attempt, Attempt::AnswerRefused);
        assert_eq!(
            e.text,
            "The connection to \"Desk\" ended: protocol violation E_BAD_SIG: signature."
        );
        assert_eq!(e.reason, "error");
        let above = ended(
            &HandshakeError::AnswerRefused {
                code: codes::E_BAD_STATE,
                what: "mode above the request",
            },
            "Desk",
        );
        assert_eq!(above.attempt, Attempt::AnswerRefused);
        assert_eq!(above.reason, "above_the_request");
        let (_tmp, paths, vault, saved) = with_vault();
        let h = host(13);
        assert!(
            settle(&paths, &saved, &h, ACCEPTED, &typed("pw", true))
                .unwrap()
                .remembered
        );
        let attempt = ended(&hello_ack, "Desk").attempt;
        assert!(
            settle(&paths, &saved, &h, attempt, &typed("pw", false))
                .unwrap()
                .remembered
        );
        assert_eq!(vault.names().len(), 1);
    }

    /// A24, `reach` cleared in the file: Remember shows once, and an answer of 1 still
    /// keeps nothing (C8).
    #[test]
    fn a24_reach_cleared_shows_remember_and_keeps_nothing_at_1() {
        use tornect_core::unattended::credentials::RememberOffer;
        let (_tmp, paths, vault, saved) = with_vault();
        let h = host(20);
        settle(&paths, &saved, &h, ONE, &typed("pw", false)).unwrap();
        assert!(record(&paths, &h).reach);
        edit(&paths, &h, |r| r.reach = false);
        assert_eq!(
            saved.offer(record(&paths, &h).reach),
            RememberOffer::Offered
        );
        let s = settle(&paths, &saved, &h, ONE, &typed("pw", true)).unwrap();
        assert!(!s.remembered);
        assert!(vault.names().is_empty());
        let r = record(&paths, &h);
        assert!(r.reach && !r.remember);
    }

    /// A24, `reach` set in the file: Remember is not offered, so nothing is written; the
    /// next answer of 0 clears it again (C1, C8).
    #[test]
    fn a24_reach_set_writes_nothing() {
        use tornect_core::unattended::credentials::RememberOffer;
        let (_tmp, paths, vault, saved) = with_vault();
        let h = host(21);
        settle(&paths, &saved, &h, ACCEPTED, &typed("pw", false)).unwrap();
        edit(&paths, &h, |r| r.reach = true);
        assert_eq!(
            saved.offer(record(&paths, &h).reach),
            RememberOffer::NotForAdministrator
        );
        let s = settle(&paths, &saved, &h, ACCEPTED, &typed("pw", false)).unwrap();
        assert!(!s.remembered);
        assert!(vault.names().is_empty());
        assert!(!record(&paths, &h).reach);
    }

    /// A24, `remember` set for a host never remembered: recall reads only that host's
    /// derived entry, never another host's password (C8).
    #[test]
    fn a24_remember_set_recalls_only_that_hosts_entry() {
        let (_tmp, paths, vault, saved) = with_vault();
        let (kept, never) = (host(22), host(23));
        assert!(
            settle(&paths, &saved, &kept, ACCEPTED, &typed("kept", true))
                .unwrap()
                .remembered
        );
        edit(&paths, &never, |r| r.remember = true);
        assert_eq!(recall(&paths, &saved, &never).unwrap(), None);
        assert!(matches!(
            recall_for_use(&paths, &saved, &never).unwrap(),
            Recalled::Vanished
        ));
        assert_eq!(vault.names().len(), 1);
    }

    /// A24, hosts.toml rolled back after a deletion: the flag comes back with the file, the
    /// password does not.
    #[test]
    fn a24_rolled_back_after_a_deletion_brings_nothing_back() {
        let (_tmp, paths, vault, saved) = with_vault();
        let h = host(24);
        assert!(
            settle(&paths, &saved, &h, ACCEPTED, &typed("pw", true))
                .unwrap()
                .remembered
        );
        let before = std::fs::read(paths.hosts_file()).unwrap();
        settle(&paths, &saved, &h, ONE, &typed("pw", false)).unwrap();
        assert!(vault.names().is_empty());
        std::fs::write(paths.hosts_file(), &before).unwrap();
        assert!(record(&paths, &h).remember);
        assert_eq!(recall(&paths, &saved, &h).unwrap(), None);
        assert!(vault.names().is_empty());
    }

    /// A24, hosts.toml unreadable at an answer of 1: the entry is still deleted, and the
    /// error is the file's (C2).
    #[test]
    fn a24_unreadable_at_an_answer_of_1_still_deletes() {
        let (_tmp, paths, vault, saved) = with_vault();
        let h = host(29);
        assert!(
            settle(&paths, &saved, &h, ACCEPTED, &typed("pw", true))
                .unwrap()
                .remembered
        );
        std::fs::write(paths.hosts_file(), "not = [valid").unwrap();
        let err = settle(&paths, &saved, &h, ONE, &typed("pw", false)).unwrap_err();
        assert!(
            err.downcast_ref::<tornect_core::CoreError>()
                .is_some_and(|e| matches!(e, tornect_core::CoreError::HostsParse { .. })),
            "{err:#}"
        );
        assert!(vault.names().is_empty());
    }

    /// A24, a keychain delete that fails (C7): `remember` stays set, nothing is kept, and
    /// the check when the prompt opens deletes the entry once the keychain lets it (C6).
    #[test]
    fn a24_a_failed_delete_keeps_remember_and_the_prompt_deletes_it() {
        let (_tmp, paths, vault, saved) = with_vault();
        let h = host(25);
        assert!(
            settle(&paths, &saved, &h, ACCEPTED, &typed("pw", true))
                .unwrap()
                .remembered
        );
        vault.refuse_deletes(true);
        let s = settle(&paths, &saved, &h, ONE, &typed("pw", true)).unwrap();
        assert!(s.delete_failed && !s.remembered && !s.forgot);
        assert_eq!(vault.names().len(), 1);
        let r = record(&paths, &h);
        assert!(r.remember && r.reach);
        assert_eq!(belt(&paths, &saved, &h).unwrap(), Some(Deleted::Refused));
        assert!(record(&paths, &h).remember);
        vault.refuse_deletes(false);
        assert_eq!(belt(&paths, &saved, &h).unwrap(), Some(Deleted::Entry));
        assert!(vault.names().is_empty());
        assert!(!record(&paths, &h).remember);
        assert_eq!(belt(&paths, &saved, &h).unwrap(), None);
    }

    /// A24, a crash between the accept and the save (a file that cannot be written stands
    /// for it): nothing is kept for an answer of 1.
    #[test]
    fn a24_a_crash_before_the_save_keeps_nothing_at_1() {
        let (_tmp, paths, vault, saved) = with_vault();
        let h = host(26);
        assert!(
            settle(&paths, &saved, &h, ACCEPTED, &typed("pw", true))
                .unwrap()
                .remembered
        );
        let tmp_file = paths.hosts_file().with_extension("toml.tmp");
        std::fs::create_dir_all(&tmp_file).unwrap();
        assert!(settle(&paths, &saved, &h, ONE, &typed("pw", true)).is_err());
        assert!(vault.names().is_empty(), "{:?}", vault.names());
    }

    /// A24, a reject after F2 (`COOLDOWN`) with a remembered entry, then an answer of 0 to
    /// the recalled password: both keep the entry and the flags.
    #[test]
    fn a24_a_reject_then_a_zero_keep_the_entry_and_the_flags() {
        let (_tmp, paths, vault, saved) = with_vault();
        let h = host(27);
        assert!(
            settle(&paths, &saved, &h, ACCEPTED, &typed("pw", true))
                .unwrap()
                .remembered
        );
        let before = record(&paths, &h);
        let cooldown = ended(
            &HandshakeError::SessionRejected {
                reject: Box::new(rejected(reject::COOLDOWN)),
            },
            "Desk",
        );
        assert_eq!(cooldown.attempt, Attempt::Inconclusive);
        assert!(
            settle(&paths, &saved, &h, cooldown.attempt, &typed("pw", false))
                .unwrap()
                .remembered
        );
        assert_eq!(record(&paths, &h), before);
        let Recalled::Password(password) = recall_for_use(&paths, &saved, &h).unwrap() else {
            panic!("the remembered password");
        };
        let recalled = Request {
            password,
            view_only: false,
            administrator: false,
            remember: false,
        };
        assert!(
            settle(&paths, &saved, &h, ACCEPTED, &recalled)
                .unwrap()
                .remembered
        );
        assert_eq!(record(&paths, &h), before);
        assert_eq!(vault.names().len(), 1);
    }

    /// A24, Forget while the keychain refuses the delete: Forget says so and keeps the
    /// record with `remember` set; a later Forget deletes the entry.
    #[test]
    fn a24_forget_while_the_keychain_refuses_keeps_the_record() {
        let (_tmp, paths, vault, saved) = with_vault();
        let h = host(28);
        assert!(
            settle(&paths, &saved, &h, ACCEPTED, &typed("pw", true))
                .unwrap()
                .remembered
        );
        vault.refuse_deletes(true);
        assert!(matches!(forget(&paths, &saved, &h), Err(Kept::Password(_))));
        assert!(record(&paths, &h).remember);
        assert_eq!(vault.names().len(), 1);
        vault.refuse_deletes(false);
        forget(&paths, &saved, &h).unwrap();
        assert!(vault.names().is_empty());
        assert_eq!(
            record(&paths, &h),
            tornect_core::unattended::hosts::HostRecord::default()
        );
    }

    /// The host as the notes name it.
    const DESK: &str = "\"Desk\"";

    /// A session answer for the notes: control asked and given, nothing withheld.
    fn session(grant_reach: Option<u8>) -> Answered {
        Answered::Session {
            elevation: tornect_core::levels::Elevation::None,
            grant_reach,
            asked_control: true,
            given_control: true,
            withheld: false,
        }
    }

    /// What `settle` did, for the notes.
    fn did(forgot: bool, delete_failed: bool) -> Settled {
        Settled {
            forgot,
            delete_failed,
            ..Settled::default()
        }
    }

    /// M1-67 copy, answer 2: Remember ticked, nothing kept, and only then the note.
    #[test]
    fn the_note_for_an_answer_of_2() {
        let said = "The password was not remembered: \"Desk\" lets your access use administrator \
                    access through Tornect.";
        assert_eq!(
            notes(DESK, "K", session(Some(2)), true, Some(&did(false, false))),
            [said]
        );
        assert!(notes(DESK, "K", session(Some(2)), false, Some(&did(false, false))).is_empty());
        assert!(notes(DESK, "K", session(Some(0)), true, Some(&did(false, false))).is_empty());
    }

    /// M1-67 copy, answer 1 (the host over-reports on purpose).
    #[test]
    fn the_note_for_an_answer_of_1() {
        let said = "The password was not remembered: \"Desk\" says your access there can reach \
                    administrator access through Tornect, or could not rule it out.";
        assert_eq!(
            notes(DESK, "K", session(Some(1)), true, Some(&did(false, false))),
            [said]
        );
        assert!(notes(DESK, "K", session(Some(1)), false, Some(&did(false, false))).is_empty());
    }

    /// M1-67 copy: a remembered password deleted at 1 or 2; "Type it each time." only
    /// when the signed mode was control, never after an admin command.
    #[test]
    fn the_note_for_a_password_deleted_at_reach() {
        let deleted = "The password remembered for \"Desk\" was deleted: \"Desk\" now says your \
                       access there can reach administrator access through Tornect, or could \
                       not rule it out.";
        for reach in [Some(1), Some(2)] {
            assert_eq!(
                notes(DESK, "K", session(reach), false, Some(&did(true, false))),
                [format!("{deleted} Type it each time.")]
            );
            let view = Answered::Session {
                elevation: tornect_core::levels::Elevation::None,
                grant_reach: reach,
                asked_control: false,
                given_control: false,
                withheld: false,
            };
            assert_eq!(
                notes(DESK, "K", view, false, Some(&did(true, false))),
                [deleted]
            );
            let admin = Answered::Admin { grant_reach: reach };
            assert_eq!(
                notes(DESK, "K", admin, false, Some(&did(true, false))),
                [deleted]
            );
        }
    }

    /// M1-67 copy: control asked, the signed mode view only and `grant_reach` 1 or 2: the
    /// view-only note; not at 0, and not without the key.
    #[test]
    fn the_view_only_note() {
        let said = "\"Desk\" gave this session view only. Its owner can bring control back, for \
                    example by giving this device a new password.";
        let lowered = |grant_reach| Answered::Session {
            elevation: tornect_core::levels::Elevation::None,
            grant_reach,
            asked_control: true,
            given_control: false,
            withheld: false,
        };
        for reach in [Some(1), Some(2)] {
            assert_eq!(
                notes(DESK, "K", lowered(reach), false, Some(&did(false, false))),
                [said]
            );
        }
        assert!(notes(DESK, "K", lowered(Some(0)), false, Some(&did(false, false))).is_empty());
        assert!(notes(DESK, "K", lowered(None), false, Some(&did(false, false))).is_empty());
    }

    /// M1-67 copy: an answer without `grant_reach` (an older host): not remembered, or the
    /// remembered one deleted; nothing to say when neither.
    #[test]
    fn the_note_for_an_absent_key() {
        assert_eq!(
            notes(DESK, "K", session(None), true, Some(&did(false, false))),
            [
                "\"Desk\" runs an older Tornect that does not say what your access can reach \
              there, so the password is not remembered."
            ]
        );
        assert_eq!(
            notes(
                DESK,
                "K",
                Answered::Admin { grant_reach: None },
                false,
                Some(&did(true, false))
            ),
            [
                "\"Desk\" runs an older Tornect that does not say what your access can reach \
              there, so the password remembered for it was deleted."
            ]
        );
        assert!(notes(DESK, "K", session(None), false, Some(&did(false, false))).is_empty());
    }

    /// M1-67 copy: a refused answer that deleted a remembered password says so.
    #[test]
    fn the_note_for_a_refused_answer() {
        assert_eq!(
            notes(DESK, "K", Answered::Refused, false, Some(&did(true, false))),
            [
                "\"Desk\" sent an answer this device could not check; the password remembered \
              for it was deleted."
            ]
        );
        assert!(notes(DESK, "K", Answered::Refused, true, Some(&did(false, false))).is_empty());
    }

    /// M1-67 copy, C7: the keychain refused the delete.
    #[test]
    fn the_note_for_a_failed_delete() {
        assert_eq!(
            notes(
                DESK,
                "Windows Credential Manager",
                session(Some(1)),
                false,
                Some(&did(false, true))
            ),
            [
                "The password remembered for \"Desk\" could not be deleted from Windows Credential \
              Manager. Tornect tries again when you next connect; Forget \"Desk\" also deletes \
              it."
            ]
        );
    }

    /// M1-67 copy: the level asked for and not given.
    #[test]
    fn the_note_for_the_level_not_given() {
        let withheld = Answered::Session {
            elevation: tornect_core::levels::Elevation::None,
            grant_reach: Some(0),
            asked_control: true,
            given_control: true,
            withheld: true,
        };
        assert_eq!(
            notes(DESK, "K", withheld, false, Some(&did(false, false))),
            [
                "\"Desk\" did not give administrator access to this session. The session goes on \
              without it."
            ]
        );
    }

    /// F4-4: the Unlock confirmation says that the other device's lock is
    /// reset and that a suspension set from another of your devices is lifted.
    #[test]
    fn the_unlock_confirmation_says_what_it_does() {
        assert_eq!(
            AdminAction::Unlock.confirmation("Desk"),
            "Unlock your other device at \"Desk\"? Its wrong-password lock is reset there, and \
             a suspension set from another of your devices is lifted."
        );
    }

    #[test]
    fn a_request_says_nothing_of_its_password() {
        let r = Request {
            password: Zeroizing::new("quiet verdant otter".to_owned()),
            view_only: true,
            administrator: false,
            remember: false,
        };
        assert!(!format!("{r:?}").contains("otter"));
        match r.intent() {
            tornect_signal::fsm::client::Intent::Unattended(ua) => {
                assert_eq!(ua.want_mode, messages::mode::VIEW_ONLY);
                assert_eq!(ua.want_elevation, tornect_core::levels::Elevation::None);
            }
            other => panic!("{other:?}"),
        }
    }
}
