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

use tornect_core::session_log::{SessionEvent, SessionLog, SessionMode, SessionRecord};
use tornect_core::trusted::KnownHost;
use tornect_core::unattended::credentials::{Attempt, SavedPasswords};
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

/// One writer of `hosts.toml` at a time in this process: the FSM's pin and the
/// remembered-password bookkeeping both load, change and save it.
fn hosts_lock() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(PoisonError::into_inner)
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
        let _one = hosts_lock();
        match HostsFile::load(&self.path) {
            Ok(file) => file.check_pin(host, server_s_pk),
            Err(e) => {
                tracing::warn!(error = %e, "hosts.toml could not be read: the host's key cannot be checked");
                PinCheck::Mismatch
            }
        }
    }

    fn record(&self, host: &TornectId, server_s_pk: &[u8; 32]) {
        let _one = hosts_lock();
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
    let _one = hosts_lock();
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
    let _one = hosts_lock();
    let file = HostsFile::load(&paths.hosts_file())?;
    Ok(saved.recall(&file, host)?)
}

/// Forget `host`'s unattended record and delete its remembered password (Forget).
pub fn forget(paths: &Paths, saved: &SavedPasswords, host: &TornectId) -> anyhow::Result<()> {
    let _one = hosts_lock();
    let path = paths.hosts_file();
    let mut file = HostsFile::load(&path)?;
    saved.forget(&mut file, host)?;
    if file.remove(host) {
        file.save(&path)?;
    }
    Ok(())
}

/// Delete every remembered password of this home (Rotate ID); how many went.
pub fn forget_all(paths: &Paths, saved: &SavedPasswords) -> anyhow::Result<usize> {
    let _one = hosts_lock();
    let path = paths.hosts_file();
    let mut file = HostsFile::load(&path)?;
    let hosts: Vec<TornectId> = file
        .hosts
        .iter()
        .filter(|(_, r)| r.remember)
        .filter_map(|(onion, _)| onion.parse().ok())
        .collect();
    for host in &hosts {
        saved.forget(&mut file, host)?;
    }
    if !hosts.is_empty() {
        file.save(&path)?;
    }
    Ok(hosts.len())
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
        HandshakeError::Violation { code, what }
            if *code == codes::E_BAD_STATE && what.contains("above the request") =>
        {
            plain(
                Attempt::Inconclusive,
                format!(
                    "\"{host}\" answered with more access than this device asked for, which it must \
                 never do; the connection was closed."
                ),
                "above_the_request",
            )
        }
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

/// Settle one attempt at `host`: a refused password stale and deleted, an accepted
/// one kept when Remember was ticked and allowed (DA-14), `hosts.toml` saved when it
/// changed. Returns whether a password is remembered for the host now.
pub fn settle(
    paths: &Paths,
    saved: &SavedPasswords,
    host: &TornectId,
    attempt: Attempt,
    request: &Request,
) -> anyhow::Result<bool> {
    let _one = hosts_lock();
    let path = paths.hosts_file();
    let mut file = HostsFile::load(&path)?;
    let keep = request.remember.then_some(request.password.as_str());
    let settled = saved.settle(&mut file, host, attempt, keep)?;
    if settled.changed {
        file.save(&path)?;
    }
    Ok(settled.remembered)
}

/// Record the signed mode of an accepted session at `host` (the host card
/// offers the control grants' admin actions from it).
pub fn note_mode(paths: &Paths, host: &TornectId, control: bool) -> anyhow::Result<()> {
    let _one = hosts_lock();
    let path = paths.hosts_file();
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
    let _one = hosts_lock();
    let path = paths.hosts_file();
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
                "Unlock your other device at \"{host}\"? Its wrong-password lock is reset there."
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
            &HandshakeError::Violation {
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
