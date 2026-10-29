//! OS re-authentication (`docs/PLAN.md` §B.8.6.2, §B.8.14).
//!
//! [`tornect_core::unattended::guard::ReAuth`] is the gate in front of every
//! access-increasing mutation: creating a grant, enabling one, resuming a
//! suspended one, changing autostart, exporting a backup. Its contract is a
//! **blocking OS dialog, a fresh one per operation** — the point is that a
//! human at the host answers it, so an attacker who reaches the CLI or the IPC
//! socket still cannot widen access.
//!
//! What this cannot do, stated plainly: an OS re-auth dialog is not a defence
//! against code already running as the same user with the user present. It
//! raises the cost of silent, unattended widening — a script, a stolen shell, a
//! forgotten session — which is the threat §B.8.6.2 names. Any claim beyond
//! that would be false comfort.

use std::sync::atomic::{AtomicUsize, Ordering};

use tornect_core::unattended::guard::{ReAuth, ReAuthError};

/// Environment variable that waives the dialog in **debug builds only**.
///
/// §B.8.14's M1 row asks for exactly this: the dev machine has no way to answer
/// a real dialog inside a test, and a build that could be talked out of
/// re-authentication by an environment variable must never ship.
pub const DEV_ESCAPE_ENV: &str = "TORNECT_DEV_REAUTH";

/// The value [`DEV_ESCAPE_ENV`] must hold for the escape to apply.
pub const DEV_ESCAPE_VALUE: &str = "allow";

/// A `ReAuth` that always refuses.
///
/// The default wherever no OS backend is available. Refusing is the only safe
/// default: a missing backend must block access-increasing operations, never
/// wave them through.
#[derive(Debug, Clone, Copy, Default)]
pub struct RefuseReAuth;

impl ReAuth for RefuseReAuth {
    fn reauthenticate(&self, op: &str) -> Result<(), ReAuthError> {
        tracing::warn!(
            op,
            "re-authentication refused: no OS backend on this platform"
        );
        Err(ReAuthError::Unavailable(
            "no OS re-authentication backend is available on this host".to_owned(),
        ))
    }
}

/// The debug-build escape of §B.8.14, honoured only when
/// `TORNECT_DEV_REAUTH=allow` **and** this is a debug build.
///
/// In a release build it degrades to [`RefuseReAuth`] — not by convention but
/// by `cfg(debug_assertions)`, so there is no code path in a shipped binary
/// that reads the variable at all.
#[derive(Debug, Default)]
pub struct DevReAuth {
    calls: AtomicUsize,
}

impl DevReAuth {
    /// A fresh escape.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many times the dialog was waived (tests, and the startup warning).
    #[must_use]
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// Whether the escape is armed in this build and environment.
    #[must_use]
    pub fn armed() -> bool {
        cfg!(debug_assertions) && std::env::var(DEV_ESCAPE_ENV).as_deref() == Ok(DEV_ESCAPE_VALUE)
    }
}

impl ReAuth for DevReAuth {
    fn reauthenticate(&self, op: &str) -> Result<(), ReAuthError> {
        if Self::armed() {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tracing::warn!(
                op,
                "re-authentication WAIVED by TORNECT_DEV_REAUTH (debug build)"
            );
            return Ok(());
        }
        RefuseReAuth.reauthenticate(op)
    }
}

// ---------------------------------------------------------------------------
// Windows: the secure credential prompt, verified with LogonUserW
// ---------------------------------------------------------------------------

/// What the Windows dialog says the password is for, per operation class —
/// the same five classes as the polkit actions, so both OSes tell the user
/// the same thing; installing and removing Tornect, which polkit counts as
/// autostart changes, and the banner's acknowledgement, which polkit counts as
/// a settings change, are named as what they are.
#[must_use]
pub fn purpose_of(op: &str) -> &'static str {
    match op {
        "create_grant" | "set_password" | "reg_start" => {
            "give a device unattended access to this computer, or change its password"
        }
        "master_on" | "enable" | "resume" | "unlock" => {
            "turn unattended access back on for this computer"
        }
        "service_install" | "service_uninstall" => "change what starts when you log in",
        "install" => "install Tornect on this computer",
        "uninstall" => "remove Tornect from this computer",
        // §B.8.7.5's copy, at the moment of consent (slice-F F1-3).
        "service_install_elevated" => {
            "start the Tornect host ELEVATED at every login. Running the host elevated makes every \
             remote Control session an administrator session"
        }
        "backup_export" | "backup_import" | "identity_view" => "export or import Tornect's secrets",
        "set_settings" | "set_options" | "settings_change" => "change a Tornect security setting",
        "acknowledge_banner" => {
            "confirm that you have seen which devices can connect without asking"
        }
        // The strongest wording for an operation this build does not know.
        _ => "give a device unattended access to this computer, or change its password",
    }
}

/// What the Windows dialog says the password is for when a registration gives the
/// device labelled `device` administrator access, or reach to it (decision M1-67, D3):
/// "give `<device>` ADMINISTRATOR access to this computer, with a new password". The label
/// is the grant's pinned label, sanitized when it was stored.
#[must_use]
pub fn raise_purpose(device: &str) -> String {
    format!("give {device} ADMINISTRATOR access to this computer, with a new password")
}

/// A credential typed into the Windows prompt.
///
/// The password is kept as the NUL-terminated UTF-16 that `LogonUserW` takes,
/// in a buffer wiped on drop; `Debug` never prints it, and neither the user
/// name nor the password is ever logged.
pub struct PromptedCredential {
    user: String,
    domain: String,
    password: zeroize::Zeroizing<Vec<u16>>,
}

impl PromptedCredential {
    /// A credential from the prompt's answer. `password` must hold a NUL; a
    /// missing one is appended.
    #[must_use]
    pub fn new(user: String, domain: String, mut password: zeroize::Zeroizing<Vec<u16>>) -> Self {
        if !password.contains(&0) {
            password.push(0);
        }
        Self {
            user,
            domain,
            password,
        }
    }

    /// The user name as typed (`DOMAIN\user`, `user@domain` or `user`).
    #[must_use]
    pub fn user(&self) -> &str {
        &self.user
    }

    /// The domain the prompt returned separately, often empty.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// The password, NUL-terminated UTF-16.
    #[must_use]
    pub fn password_wide(&self) -> &[u16] {
        &self.password
    }
}

impl std::fmt::Debug for PromptedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PromptedCredential")
            .field("user", &"<redacted>")
            .field("password", &"<redacted>")
            .finish()
    }
}

/// `LogonUserW`'s account and domain for a typed name: a separate domain
/// wins; `DOMAIN\user` splits; a UPN (`user@domain`) goes whole with no domain
/// (`LogonUserW` requires that); a bare name is looked up in the local
/// account database (`.`).
#[must_use]
pub fn logon_names(user: &str, domain: &str) -> (String, Option<String>) {
    if !domain.is_empty() {
        return (user.to_owned(), Some(domain.to_owned()));
    }
    if let Some((dom, name)) = user.split_once('\\') {
        return (name.to_owned(), Some(dom.to_owned()));
    }
    if user.contains('@') {
        return (user.to_owned(), None);
    }
    (user.to_owned(), Some(".".to_owned()))
}

/// What the credential prompt returned.
#[derive(Debug)]
pub enum PromptOutcome {
    /// The user typed a credential.
    Entered(PromptedCredential),
    /// The user dismissed the dialog.
    Cancelled,
    /// The dialog could not be shown or read (an error code, never a name).
    Failed(String),
}

/// What checking a credential with the OS said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogonOutcome {
    /// A logon succeeded and its token belongs to the user running Tornect.
    CurrentUser,
    /// A logon succeeded for **another** account.
    OtherUser,
    /// The OS refused the credential (wrong password, unknown account).
    Rejected,
    /// The check itself failed (an error code, never a name).
    Failed(String),
}

/// Shows the credential dialog (the seam: the Windows implementation calls
/// `CredUIPromptForWindowsCredentialsW` with `CREDUIWIN_SECURE_PROMPT`; tests
/// script it on any OS).
pub trait CredentialPrompt: Send + Sync {
    /// Ask for the password, saying what it is for.
    fn prompt(&self, purpose: &str) -> PromptOutcome;
}

/// Checks a credential (the seam: the Windows implementation calls
/// `LogonUserW(LOGON32_LOGON_INTERACTIVE)` and compares the token's user SID
/// with this process's).
pub trait LogonCheck: Send + Sync {
    /// Whether `credential` logs on as the user running Tornect.
    fn verify(&self, credential: &PromptedCredential) -> LogonOutcome;
}

/// The Windows backend of §B.8.8: the credential dialog on the secure desktop
/// (`CREDUIWIN_SECURE_PROMPT`, where no other program — and no remote viewer —
/// can read or drive it), then `LogonUserW` to verify what was typed.
///
/// Success only for a verified logon **as the user running Tornect**: a
/// cancelled dialog, a refused password, another account's valid password or
/// any error refuses. The typed password lives in a wiped buffer for the few
/// calls that need it; only the outcome kind is logged.
///
/// The dialog and the check of what was typed run on a thread of their own,
/// and the operation waits for them at most [`Self::DIALOG_TIMEOUT`]: past
/// it, it is refused (`Denied`, logged `timed_out`), and a credential typed
/// later is wiped without being checked (audit B18). A dialog left open
/// used to keep the operation waiting with no bound, so the command line
/// gave up after [`crate::ipc::RESPONSE_TIMEOUT`] and said so, and the
/// operation was applied when the password came. CredUI has no call that
/// closes its dialog, so it stays on the secure desktop until answered or
/// cancelled, and until then no other dialog opens.
///
/// Limits, stated plainly: a Windows Hello PIN or fingerprint is not a password
/// `LogonUserW` can check, so the user must pick the password option in the
/// dialog (NEEDS-DEVICE); an account with an empty password cannot be verified
/// at all (`LogonUserW` refuses a blank password for an interactive logon by
/// default), so such a host cannot make access-increasing changes — fail
/// closed. As on every OS, this proves a human at the host knows the OS
/// credential; it does not stop code already running as this user.
pub struct WindowsReAuth {
    prompt: std::sync::Arc<dyn CredentialPrompt>,
    logon: std::sync::Arc<dyn LogonCheck>,
    /// One dialog at a time, never a queue (as the polkit backend's: track D
    /// S1/S6): held by the dialog's thread until the dialog really returns,
    /// even after the operation stopped waiting for it.
    dialog: std::sync::Arc<std::sync::Mutex<()>>,
    /// How long an operation waits for the dialog and the logon check.
    timeout: std::time::Duration,
}

impl std::fmt::Debug for WindowsReAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WindowsReAuth").finish_non_exhaustive()
    }
}

impl WindowsReAuth {
    /// How long an operation waits for the dialog and the check of what was
    /// typed before it is refused: polkit's dialog bound
    /// (`PolkitReAuth::DIALOG_TIMEOUT`), the registration transaction's own
    /// 120 s life (§B.8.7.4), and below [`crate::ipc::RESPONSE_TIMEOUT`], so
    /// the host answers before the command line stops waiting.
    pub const DIALOG_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

    /// The OS dialog and `LogonUserW`.
    #[cfg(windows)]
    #[must_use]
    pub fn new() -> Self {
        Self::with_backends(
            Box::new(crate::win::SecurePrompt),
            Box::new(crate::win::LogonUserCheck),
        )
    }

    /// The flow over any prompt and logon check (tests on every OS).
    #[must_use]
    pub fn with_backends(prompt: Box<dyn CredentialPrompt>, logon: Box<dyn LogonCheck>) -> Self {
        Self {
            prompt: std::sync::Arc::from(prompt),
            logon: std::sync::Arc::from(logon),
            dialog: std::sync::Arc::default(),
            timeout: Self::DIALOG_TIMEOUT,
        }
    }

    /// Override how long an operation waits for the dialog (tests).
    #[must_use]
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

#[cfg(windows)]
impl Default for WindowsReAuth {
    fn default() -> Self {
        Self::new()
    }
}

impl ReAuth for WindowsReAuth {
    fn reauthenticate(&self, op: &str) -> Result<(), ReAuthError> {
        self.ask(op, purpose_of(op))
    }

    /// Decision M1-67 (D3): the dialog of a registration that gives `device` administrator
    /// access, or reach to it, names both.
    fn reauthenticate_raise(&self, device: &str) -> Result<(), ReAuthError> {
        self.ask("raise", &raise_purpose(device))
    }
}

impl WindowsReAuth {
    /// One dialog saying the password is for `purpose`, then the logon check, on a thread
    /// of their own, waited for at most the timeout; `op` names the operation in the log.
    fn ask(&self, op: &str, purpose: &str) -> Result<(), ReAuthError> {
        let deadline = std::time::Instant::now() + self.timeout;
        let (tx, rx) = std::sync::mpsc::channel();
        let (prompt, logon, dialog) = (
            std::sync::Arc::clone(&self.prompt),
            std::sync::Arc::clone(&self.logon),
            std::sync::Arc::clone(&self.dialog),
        );
        let (op_owned, purpose) = (op.to_owned(), purpose.to_owned());
        let started = std::thread::Builder::new()
            .name("reauth-dialog".to_owned())
            // An explicit size: std then never reads `RUST_MIN_STACK`.
            .stack_size(2 * 1024 * 1024)
            .spawn(move || {
                let verdict = dialog_flow(&*prompt, &*logon, &dialog, &op_owned, &purpose, deadline);
                // An operation that stopped waiting drops the late verdict here.
                let _ = tx.send(verdict);
            });
        if let Err(e) = started {
            tracing::warn!(
                op,
                outcome = "prompt_failed",
                "re-authentication unavailable"
            );
            return Err(ReAuthError::Unavailable(format!(
                "the re-authentication dialog could not be started: {e}"
            )));
        }
        match rx.recv_timeout(self.timeout) {
            Ok(verdict) => verdict,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                tracing::info!(
                    op,
                    outcome = "timed_out",
                    "re-authentication was not granted"
                );
                Err(ReAuthError::Denied)
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                tracing::warn!(op, outcome = "prompt_failed", "re-authentication failed");
                Err(ReAuthError::Failed(
                    "the re-authentication dialog ended without an answer".to_owned(),
                ))
            }
        }
    }
}

/// [`WindowsReAuth::ask`]'s dialog and logon check, on the dialog's own thread: one
/// dialog at a time (`dialog` held until it returns); a credential typed after `deadline`,
/// when the operation has stopped waiting, is wiped and never checked.
fn dialog_flow(
    prompt: &dyn CredentialPrompt,
    logon: &dyn LogonCheck,
    dialog: &std::sync::Mutex<()>,
    op: &str,
    purpose: &str,
    deadline: std::time::Instant,
) -> Result<(), ReAuthError> {
    let _open = match dialog.try_lock() {
        Ok(held) => held,
        Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
        Err(std::sync::TryLockError::WouldBlock) => {
            return Err(ReAuthError::Unavailable(
                "another Tornect re-authentication dialog is already open; answer or \
                 cancel it, then retry"
                    .to_owned(),
            ));
        }
    };
    let verdict = match prompt.prompt(purpose) {
        PromptOutcome::Cancelled => {
            tracing::info!(
                op,
                outcome = "cancelled",
                "re-authentication was not granted"
            );
            return Err(ReAuthError::Denied);
        }
        PromptOutcome::Failed(why) => {
            tracing::warn!(
                op,
                outcome = "prompt_failed",
                "re-authentication unavailable"
            );
            return Err(ReAuthError::Unavailable(why));
        }
        // Too late: the operation was refused already. The credential is
        // dropped, and its password wiped, unchecked.
        PromptOutcome::Entered(_) if std::time::Instant::now() >= deadline => {
            tracing::info!(
                op,
                outcome = "too_late",
                "a password typed after the re-authentication timed out was not checked"
            );
            return Err(ReAuthError::Denied);
        }
        // The credential is dropped, and its password wiped, at the end
        // of this arm.
        PromptOutcome::Entered(credential) => logon.verify(&credential),
    };
    match verdict {
        LogonOutcome::CurrentUser => {
            tracing::info!(op, outcome = "verified", "re-authenticated");
            Ok(())
        }
        LogonOutcome::OtherUser => {
            tracing::info!(
                op,
                outcome = "other_user",
                "re-authentication was not granted"
            );
            Err(ReAuthError::Denied)
        }
        LogonOutcome::Rejected => {
            tracing::info!(
                op,
                outcome = "rejected",
                "re-authentication was not granted"
            );
            Err(ReAuthError::Denied)
        }
        LogonOutcome::Failed(why) => {
            tracing::warn!(op, outcome = "logon_failed", "re-authentication failed");
            Err(ReAuthError::Failed(why))
        }
    }
}

// ---------------------------------------------------------------------------
// Linux: polkit
// ---------------------------------------------------------------------------

/// The Linux backend: polkit's `CheckAuthorization` over the system D-Bus.
///
/// Why polkit and not PAM, given §B.8.14 says "PAM/polkit": polkit **is** the
/// PAM path. It runs the conversation itself, out of process, in its setuid
/// `polkit-agent-helper-1`, and raises the desktop's own authentication dialog
/// while doing so. A direct PAM backend would duplicate that, would need
/// `libpam` headers this dev machine does not have and cannot install, and
/// would have to be setuid or run as root to be useful. Verified on
/// 2026-09-04 against polkitd 127 on the build VM; full record in the research note
/// referenced from `docs/DEPENDENCIES.md`.
///
/// **What this buys, precisely.** It proves a human is at the host and knows
/// the OS credential. It does *not* stop code already running as this user —
/// that code can ptrace the process, preload into it, or run its own build
/// against the same state directory. The §B.8 adversary is a remote peer
/// holding a device key and the grant password with no way to answer a dialog,
/// and against that this is exactly the right barrier. Claiming more would be
/// false comfort.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
pub struct PolkitReAuth {
    /// Prefix for the registered action ids, so a packager can rename the whole
    /// set without a code change.
    action_prefix: String,
    /// How long a dialog may stay open before it is cancelled.
    timeout: std::time::Duration,
    /// Held while a dialog is open; clones share it. One dialog at a time, and
    /// never a queue: an op queued behind a dialog that may stay up for
    /// [`Self::DIALOG_TIMEOUT`] would outlive the CLI's wait for its answer and
    /// run after the CLI had reported it failed (track D S1/S6). A second
    /// access-increasing op while one dialog is open is refused at once.
    dialog: std::sync::Arc<std::sync::Mutex<()>>,
}

/// `(bba{ss})` — polkit's `CheckAuthorization` answer.
#[cfg(target_os = "linux")]
#[derive(Debug, serde::Deserialize, zbus::zvariant::Type)]
struct AuthorizationResult {
    is_authorized: bool,
    is_challenge: bool,
    details: std::collections::HashMap<String, String>,
}

/// What an answer means for the operator.
///
/// `is_challenge` without `is_authorized`, when the call allowed interaction,
/// is polkit saying "a password would do, but nothing could ask for one": no
/// authentication agent serves the subject — an SSH session without
/// `pkttyagent`, or a host started outside any session. Reporting that as
/// `Denied` told the operator their password was wrong when no dialog was ever
/// shown (track D S7).
#[cfg(target_os = "linux")]
fn verdict(action_id: &str, result: &AuthorizationResult) -> Result<(), ReAuthError> {
    if result.is_authorized {
        return Ok(());
    }
    if result.is_challenge {
        return Err(ReAuthError::Unavailable(format!(
            "polkit could not show an authentication dialog for `{action_id}`: no \
             authentication agent is available to the Tornect host (a desktop session \
             provides one; over SSH, run `pkttyagent` for the host process)"
        )));
    }
    tracing::info!(
        action_id,
        dismissed = result.details.contains_key("polkit.dismissed"),
        "re-authentication was not granted"
    );
    Err(ReAuthError::Denied)
}

/// What a failed `CheckAuthorization` call means for the operator.
///
/// An unregistered action is not a denial: the host has no policy file, so
/// no dialog can ever be raised, and `Denied` would tell the operator they
/// typed the wrong password. The message names where the file is: in the
/// Linux release zip and in the source tree (decision M1-89).
#[cfg(target_os = "linux")]
fn call_error(action_id: &str, text: String) -> ReAuthError {
    if text.contains("is not registered") {
        ReAuthError::Unavailable(format!(
            "polkit action `{action_id}` is not registered on this host — install \
             org.tornect.policy (polkit/ in the Linux release zip, packaging/polkit/ in the \
             source) into /usr/share/polkit-1/actions/ and restart polkit ({text})"
        ))
    } else {
        ReAuthError::Failed(text)
    }
}

#[cfg(target_os = "linux")]
impl Default for PolkitReAuth {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "linux")]
impl PolkitReAuth {
    /// The default action-id prefix; the shipped policy file uses it.
    pub const DEFAULT_PREFIX: &'static str = "org.tornect";

    /// How long a dialog may stay open before `CancelCheckAuthorization` fires.
    ///
    /// Matches the registration transaction's own 120 s life (§B.8.7.4), so a
    /// dialog cannot outlive the operation it is authorising.
    pub const DIALOG_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

    /// A backend using the shipped action ids.
    #[must_use]
    pub fn new() -> Self {
        Self {
            action_prefix: Self::DEFAULT_PREFIX.to_owned(),
            timeout: Self::DIALOG_TIMEOUT,
            dialog: std::sync::Arc::default(),
        }
    }

    /// Override the action-id prefix (packaging, and the ignored live test).
    #[must_use]
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.action_prefix = prefix.into();
        self
    }

    /// Override the dialog timeout.
    #[must_use]
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Map a guard operation name to one of the registered action ids.
    ///
    /// One action per *class* rather than per operation, for a reason that is
    /// not tidiness: an unprivileged caller may not pass a `details` map to
    /// `CheckAuthorization` at all — polkit refuses the whole call with "Only
    /// trusted callers … can use CheckAuthorization() and pass details". So the
    /// operation name cannot reach the dialog as data; the only way the user
    /// sees *what* they are approving is the message attached to the action id.
    /// Five classes keep the policy file reviewable while still telling the
    /// user whether they are about to grant a device access, re-enable one,
    /// change what starts at login, or export secrets.
    #[must_use]
    pub fn action_for(&self, op: &str) -> String {
        let class = match op {
            // Hands a device unattended access, or changes the password that
            // guards it.
            "create_grant" | "set_password" | "reg_start" => "grant",
            // Re-opens access that was closed.
            "master_on" | "enable" | "resume" | "unlock" => "enable",
            // Changes what runs at login; installing or removing Tornect
            // itself (§B.1.1), which the policy file gives no class of its own.
            "service_install"
            | "service_install_elevated"
            | "service_uninstall"
            | "install"
            | "uninstall" => "autostart",
            // Moves secrets out of the store.
            "backup_export" | "backup_import" | "identity_view" => "export",
            // Policy and settings; the banner's acknowledgement too, whose
            // message is the settings one (an action of its own would change
            // the policy file).
            "set_settings" | "set_options" | "settings_change" | "acknowledge_banner" => "settings",
            // An operation this build does not know: use the most consequential
            // wording rather than the mildest, and say so in the log.
            other => {
                tracing::warn!(
                    op = other,
                    "no polkit action class for this operation; using `grant`"
                );
                "grant"
            }
        };
        format!("{}.{class}", self.action_prefix)
    }

    async fn check(&self, action_id: &str) -> Result<(), ReAuthError> {
        use std::collections::HashMap;

        use zbus::zvariant::Value;

        /// `(sa{sv})` — the polkit subject.
        #[derive(serde::Serialize, zbus::zvariant::Type)]
        struct Subject<'a> {
            kind: &'a str,
            details: HashMap<&'a str, Value<'a>>,
        }

        let conn = zbus::Connection::system()
            .await
            .map_err(|e| ReAuthError::Unavailable(format!("system D-Bus unavailable: {e}")))?;

        // `system-bus-name` with our own unique name, not `unix-process`.
        // `unix-process` carries a pid plus a start time that is not an atomic
        // guard — the race behind CVE-2017-7572, and upstream deprecated it for
        // exactly that. `unix-session` is worse: it crashed polkitd 127 on this
        // machine, twice, from two different clients.
        let unique = conn
            .unique_name()
            .ok_or_else(|| ReAuthError::Unavailable("D-Bus connection has no unique name".into()))?
            .to_string();
        let mut subject_details: HashMap<&str, Value<'_>> = HashMap::new();
        subject_details.insert("name", Value::from(unique.as_str()));
        let subject = Subject {
            kind: "system-bus-name",
            details: subject_details,
        };

        // A cancellation id lets the timeout below actually stop the dialog
        // rather than abandoning it on screen.
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|e| ReAuthError::Failed(format!("rng: {e}")))?;
        let cancellation_id = data_encoding::HEXLOWER.encode(&nonce);

        // ALLOW_USER_INTERACTION (1) so the agent raises a dialog, plus
        // ALWAYS_CHECK (2). ALWAYS_CHECK does *not* defeat a retained
        // authorization — upstream's source shows it guards only the root
        // bypass — so "a fresh dialog per operation" (§B.8.6.2) rests on the
        // policy file declaring `auth_self` rather than `auth_self_keep`. The
        // shipped policy does; a packager who changes it silently weakens the
        // guarantee, which is why the file carries a comment saying so.
        const FLAGS: u32 = 1 | 2;
        let empty: HashMap<&str, &str> = HashMap::new();

        let args = (&subject, action_id, &empty, FLAGS, cancellation_id.as_str());
        let call = conn.call_method(
            Some("org.freedesktop.PolicyKit1"),
            "/org/freedesktop/PolicyKit1/Authority",
            Some("org.freedesktop.PolicyKit1.Authority"),
            "CheckAuthorization",
            &args,
        );

        let reply = match tokio::time::timeout(self.timeout, call).await {
            Ok(r) => r,
            Err(_) => {
                // Take the dialog off the user's screen before giving up.
                let _ = conn
                    .call_method(
                        Some("org.freedesktop.PolicyKit1"),
                        "/org/freedesktop/PolicyKit1/Authority",
                        Some("org.freedesktop.PolicyKit1.Authority"),
                        "CancelCheckAuthorization",
                        &(cancellation_id.as_str(),),
                    )
                    .await;
                return Err(ReAuthError::Denied);
            }
        };

        let reply = reply.map_err(|e| call_error(action_id, e.to_string()))?;

        let result: AuthorizationResult = reply
            .body()
            .deserialize()
            .map_err(|e| ReAuthError::Failed(format!("unexpected polkit reply: {e}")))?;
        verdict(action_id, &result)
    }
}

#[cfg(target_os = "linux")]
impl ReAuth for PolkitReAuth {
    fn reauthenticate(&self, op: &str) -> Result<(), ReAuthError> {
        let _open = match self.dialog.try_lock() {
            Ok(held) => held,
            // A panic mid-dialog poisons the lock; the dialog is over either way.
            Err(std::sync::TryLockError::Poisoned(p)) => p.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                return Err(ReAuthError::Unavailable(
                    "another Tornect re-authentication dialog is already open; answer or \
                     cancel it, then retry"
                        .to_owned(),
                ));
            }
        };
        let action_id = self.action_for(op);
        // The trait contract is a *blocking* call, run on `spawn_blocking`.
        // A blocking-pool thread belongs to the runtime but is not "entered",
        // so `Handle::block_on` there is allowed and cannot panic. The offline
        // CLI has no runtime at all and gets its own current-thread one.
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => handle.block_on(self.check(&action_id)),
            Err(_) => tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| ReAuthError::Failed(format!("no tokio runtime: {e}")))?
                .block_on(self.check(&action_id)),
        }
    }
}

#[cfg(test)]
// Diagnostics in tests: `--nocapture` is how the live polkit path is inspected,
// and a test that fails without saying what polkit answered wastes the run.
#[allow(clippy::print_stderr)]
mod tests {
    use super::*;

    #[test]
    fn refuse_is_the_default_answer() {
        assert!(matches!(
            RefuseReAuth.reauthenticate("create_grant"),
            Err(ReAuthError::Unavailable(_))
        ));
    }

    /// The escape is compiled out of release builds entirely: `armed()` is
    /// `false` there whatever the environment says.
    #[test]
    fn the_dev_escape_is_debug_only() {
        assert_eq!(DevReAuth::armed(), {
            cfg!(debug_assertions)
                && std::env::var(DEV_ESCAPE_ENV).as_deref() == Ok(DEV_ESCAPE_VALUE)
        });
        if !cfg!(debug_assertions) {
            assert!(!DevReAuth::armed());
        }
    }

    /// Every operation the mutation guard can name maps to one of the five
    /// registered action ids, and an unknown one lands on the most
    /// consequential wording rather than the mildest.
    #[cfg(target_os = "linux")]
    #[test]
    fn every_guard_operation_maps_to_a_registered_action() {
        let p = PolkitReAuth::new();
        // Exactly the ids declared in packaging/polkit/org.tornect.policy.
        let registered = [
            "org.tornect.grant",
            "org.tornect.enable",
            "org.tornect.autostart",
            "org.tornect.export",
            "org.tornect.settings",
        ];
        // Every `op` string the guard passes to `ReAuth::reauthenticate`:
        // `access_increasing(..)` call sites plus `ExternalOp::name()`.
        for op in [
            "create_grant",
            "set_password",
            "reg_start",
            "master_on",
            "enable",
            "resume",
            "unlock",
            "set_settings",
            "set_options",
            "service_install",
            "service_install_elevated",
            "service_uninstall",
            "backup_export",
            "backup_import",
            "identity_view",
            "settings_change",
            "install",
            "uninstall",
        ] {
            let action = p.action_for(op);
            assert!(
                registered.contains(&action.as_str()),
                "op `{op}` maps to `{action}`, which the policy file does not declare"
            );
        }
        // §B.1.1: installing and removing Tornect ask through the autostart
        // class, the policy file unchanged.
        assert_eq!(p.action_for("install"), "org.tornect.autostart");
        assert_eq!(p.action_for("uninstall"), "org.tornect.autostart");
        assert_eq!(
            p.action_for("some_future_operation"),
            "org.tornect.grant",
            "an unknown operation must get the strongest wording, not the mildest"
        );
        // Slice-F F1-3: the elevated install is an autostart change.
        assert_eq!(
            p.action_for("service_install_elevated"),
            "org.tornect.autostart"
        );
    }

    /// Track D S7: polkit's three "not authorized" shapes map to what actually
    /// happened, so an operator is never told their password was wrong when no
    /// dialog could be shown.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_polkit_answer_maps_to_what_happened() {
        let answer = |is_authorized, is_challenge, dismissed: bool| AuthorizationResult {
            is_authorized,
            is_challenge,
            details: if dismissed {
                [("polkit.dismissed".to_owned(), "true".to_owned())].into()
            } else {
                std::collections::HashMap::new()
            },
        };
        assert!(verdict("org.tornect.grant", &answer(true, false, false)).is_ok());
        match verdict("org.tornect.grant", &answer(false, true, false)) {
            Err(ReAuthError::Unavailable(m)) => assert!(m.contains("authentication agent"), "{m}"),
            other => panic!("no agent must read as Unavailable, got {other:?}"),
        }
        assert!(matches!(
            verdict("org.tornect.grant", &answer(false, false, true)),
            Err(ReAuthError::Denied)
        ));
        assert!(matches!(
            verdict("org.tornect.grant", &answer(false, false, false)),
            Err(ReAuthError::Denied)
        ));
    }

    /// An action polkit does not know is Unavailable, never Denied, and the
    /// message says where the policy file is: in the Linux release zip and in
    /// the source tree (decision M1-89). Any other call error is Failed.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_unregistered_action_names_where_the_policy_file_is() {
        let text = "org.freedesktop.PolicyKit1.Error.Failed: Action org.tornect.grant is not \
                    registered"
            .to_owned();
        match call_error("org.tornect.grant", text) {
            ReAuthError::Unavailable(m) => {
                for said in [
                    "`org.tornect.grant` is not registered",
                    "polkit/ in the Linux release zip",
                    "packaging/polkit/ in the source",
                    "/usr/share/polkit-1/actions/",
                    "restart polkit",
                ] {
                    assert!(m.contains(said), "`{said}` not in: {m}");
                }
            }
            other => panic!("an unregistered action must read as Unavailable, got {other:?}"),
        }
        assert!(matches!(
            call_error("org.tornect.grant", "the bus went away".to_owned()),
            ReAuthError::Failed(_)
        ));
    }

    /// Track D S1/S6: a second access-increasing op while a dialog is open is
    /// refused at once — never queued behind a dialog that may outlive the CLI's
    /// wait — and it never reaches D-Bus.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_second_dialog_is_refused_while_one_is_open() {
        let p = PolkitReAuth::new();
        let clone = p.clone();
        let _open = p.dialog.lock().unwrap();
        match clone.reauthenticate("enable") {
            Err(ReAuthError::Unavailable(m)) => assert!(m.contains("already open"), "{m}"),
            other => panic!("expected an immediate refusal, got {other:?}"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_action_prefix_is_overridable_for_packaging() {
        let p = PolkitReAuth::new().with_prefix("com.example.tornect");
        assert_eq!(p.action_for("enable"), "com.example.tornect.enable");
    }

    /// An action id this host has no policy file for must report
    /// [`ReAuthError::Unavailable`], **never** [`ReAuthError::Denied`].
    ///
    /// This is the failure mode worth pinning: telling an operator their
    /// password was wrong when the real problem is a missing
    /// `/usr/share/polkit-1/actions/org.tornect.policy` sends them chasing the
    /// wrong thing. Tornect's own action ids are deliberately not installed on
    /// a dev machine, so the default prefix exercises exactly that path — and
    /// on a host with no system bus at all the connection fails, which lands on
    /// the same variant. Either way the assertion holds, so this needs neither
    /// polkit nor a human.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_unregistered_action_is_unavailable_not_denied() {
        let p = PolkitReAuth::new().with_timeout(std::time::Duration::from_secs(5));
        match p.reauthenticate("create_grant") {
            Err(ReAuthError::Unavailable(m)) => {
                eprintln!("polkit reported: {m}");
                assert!(
                    m.contains("not registered") || m.contains("D-Bus"),
                    "unhelpful message: {m}"
                );
            }
            Err(ReAuthError::Denied) => {
                panic!("a missing policy file must not be reported as a denied credential")
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    /// Live polkit check, run by hand.
    ///
    /// Ignored by default because it needs a registered action id, a running
    /// polkit and a human to answer (or dismiss) the dialog — none of which CI
    /// has. Point it at any `auth_self` action already on the machine:
    ///
    /// ```text
    /// TORNECT_TEST_POLKIT_ACTION=com.ubuntu.UnattendedUpgrade.Pending.Postpone \
    ///   cargo test -p tornect-platform -- --ignored --nocapture live_polkit
    /// ```
    ///
    /// Dismissing the dialog must produce `Denied`; an unregistered id must
    /// produce `Unavailable`, never `Denied` — telling an operator "wrong
    /// password" when the real problem is a missing policy file is the failure
    /// mode this asserts against.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs a registered polkit action and a human at the dialog"]
    fn live_polkit_round_trip() {
        let Ok(action) = std::env::var("TORNECT_TEST_POLKIT_ACTION") else {
            panic!("set TORNECT_TEST_POLKIT_ACTION to a registered auth_self action id");
        };
        // `action_for` appends the class, so strip it back off by using the
        // full id as the prefix for an op whose class is empty is not possible;
        // instead point the prefix at the action and check the class-less form.
        let (prefix, class) = action
            .rsplit_once('.')
            .expect("an action id has at least one dot");
        let op = match class {
            "grant" => "create_grant",
            "enable" => "enable",
            "autostart" => "service_install",
            "export" => "backup_export",
            "settings" => "set_settings",
            // Any other trailing segment: drive it through the `grant` class by
            // using the whole id minus that segment as the prefix.
            _ => "create_grant",
        };
        let p = PolkitReAuth::new().with_prefix(prefix);
        let resolved = p.action_for(op);
        eprintln!("checking polkit action `{resolved}` (from `{action}`)");
        match p.reauthenticate(op) {
            Ok(()) => eprintln!("AUTHORIZED"),
            Err(ReAuthError::Denied) => eprintln!("DENIED (dialog cancelled or wrong credential)"),
            Err(ReAuthError::Unavailable(m)) => eprintln!("UNAVAILABLE: {m}"),
            Err(ReAuthError::Failed(m)) => panic!("polkit call failed: {m}"),
        }
    }

    /// Without the variable set, the escape refuses like any other backend.
    #[test]
    fn an_unarmed_escape_refuses() {
        // The test process may or may not have the variable set; assert the
        // conditional behaviour rather than mutating a process-global.
        let dev = DevReAuth::new();
        let result = dev.reauthenticate("enable");
        if DevReAuth::armed() {
            assert!(result.is_ok());
            assert_eq!(dev.calls(), 1);
        } else {
            assert!(matches!(result, Err(ReAuthError::Unavailable(_))));
            assert_eq!(dev.calls(), 0);
        }
    }

    // ------------------------------------------------------------- Windows flow

    /// A scripted prompt: returns `answer` once, counting calls.
    struct FakePrompt {
        answer: std::sync::Mutex<Option<PromptOutcome>>,
        purpose: std::sync::Mutex<Option<String>>,
    }

    impl FakePrompt {
        fn new(answer: PromptOutcome) -> Self {
            Self {
                answer: std::sync::Mutex::new(Some(answer)),
                purpose: std::sync::Mutex::new(None),
            }
        }
    }

    impl CredentialPrompt for std::sync::Arc<FakePrompt> {
        fn prompt(&self, purpose: &str) -> PromptOutcome {
            *self.purpose.lock().unwrap() = Some(purpose.to_owned());
            self.answer
                .lock()
                .unwrap()
                .take()
                .unwrap_or(PromptOutcome::Cancelled)
        }
    }

    /// A scripted logon: answers `CurrentUser` only for the right user and
    /// password, `OtherUser` for the other account's right password.
    #[derive(Default)]
    struct FakeLogon {
        calls: AtomicUsize,
    }

    impl LogonCheck for std::sync::Arc<FakeLogon> {
        fn verify(&self, c: &PromptedCredential) -> LogonOutcome {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let password = String::from_utf16_lossy(
                &c.password_wide()[..c.password_wide().iter().position(|&u| u == 0).unwrap()],
            );
            match (logon_names(c.user(), c.domain()), password.as_str()) {
                ((user, Some(dom)), "right") if user == "ana" && dom == "PC" => {
                    LogonOutcome::CurrentUser
                }
                ((user, _), "theirs") if user == "bruno" => LogonOutcome::OtherUser,
                _ => LogonOutcome::Rejected,
            }
        }
    }

    fn typed(user: &str, password: &str) -> PromptOutcome {
        PromptOutcome::Entered(PromptedCredential::new(
            user.to_owned(),
            String::new(),
            zeroize::Zeroizing::new(password.encode_utf16().collect()),
        ))
    }

    fn windows(
        answer: PromptOutcome,
    ) -> (
        WindowsReAuth,
        std::sync::Arc<FakePrompt>,
        std::sync::Arc<FakeLogon>,
    ) {
        let prompt = std::sync::Arc::new(FakePrompt::new(answer));
        let logon = std::sync::Arc::new(FakeLogon::default());
        let reauth = WindowsReAuth::with_backends(
            Box::new(std::sync::Arc::clone(&prompt)),
            Box::new(std::sync::Arc::clone(&logon)),
        );
        (reauth, prompt, logon)
    }

    /// Decision M1-67 (D3): a registration that gives a device administrator access, or
    /// reach to it, asks with its own wording, naming the device; the same logon check
    /// decides.
    #[test]
    fn a_raising_registration_names_administrator_access_and_the_device() {
        assert_eq!(
            raise_purpose("Laptop"),
            "give Laptop ADMINISTRATOR access to this computer, with a new password"
        );
        let (reauth, prompt, _logon) = windows(typed("PC\\ana", "right"));
        assert_eq!(reauth.reauthenticate_raise("Laptop"), Ok(()));
        assert_eq!(
            prompt.purpose.lock().unwrap().as_deref(),
            Some("give Laptop ADMINISTRATOR access to this computer, with a new password")
        );
        let (reauth, _, _) = windows(typed("PC\\ana", "wrong"));
        assert_eq!(
            reauth.reauthenticate_raise("Laptop"),
            Err(ReAuthError::Denied)
        );
    }

    /// The Windows flow, on any OS: only a verified logon as the current user
    /// allows; cancel, a wrong password, another account and a broken prompt
    /// all refuse.
    #[test]
    fn the_windows_flow_allows_only_the_current_user() {
        let (r, prompt, logon) = windows(typed("PC\\ana", "right"));
        assert!(r.reauthenticate("service_install").is_ok());
        assert_eq!(logon.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            prompt.purpose.lock().unwrap().as_deref(),
            Some("change what starts when you log in")
        );

        let (r, _, logon) = windows(PromptOutcome::Cancelled);
        assert!(matches!(
            r.reauthenticate("service_install"),
            Err(ReAuthError::Denied)
        ));
        assert_eq!(logon.calls.load(Ordering::SeqCst), 0, "nothing to check");

        let (r, _, _) = windows(typed("PC\\ana", "wrong"));
        assert!(matches!(
            r.reauthenticate("enable"),
            Err(ReAuthError::Denied)
        ));

        let (r, _, _) = windows(typed("PC\\bruno", "theirs"));
        assert!(
            matches!(r.reauthenticate("enable"), Err(ReAuthError::Denied)),
            "another account's valid password must not authorise this user's change"
        );

        let (r, _, logon) = windows(PromptOutcome::Failed("error 1004".to_owned()));
        assert!(matches!(
            r.reauthenticate("enable"),
            Err(ReAuthError::Unavailable(_))
        ));
        assert_eq!(logon.calls.load(Ordering::SeqCst), 0);
    }

    /// A second access-increasing op while the dialog is open is refused at
    /// once and never reaches the prompt.
    #[test]
    fn a_second_windows_dialog_is_refused_while_one_is_open() {
        let (r, prompt, _) = windows(typed("PC\\ana", "right"));
        let _open = r.dialog.lock().unwrap();
        match r.reauthenticate("enable") {
            Err(ReAuthError::Unavailable(m)) => assert!(m.contains("already open"), "{m}"),
            other => panic!("expected an immediate refusal, got {other:?}"),
        }
        assert!(
            prompt.purpose.lock().unwrap().is_none(),
            "no dialog was shown"
        );
    }

    /// A dialog left open: each one shown answers the right password only
    /// once `release` says so.
    struct LeftOpen {
        shown: AtomicUsize,
        release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    }

    impl CredentialPrompt for std::sync::Arc<LeftOpen> {
        fn prompt(&self, _purpose: &str) -> PromptOutcome {
            self.shown.fetch_add(1, Ordering::SeqCst);
            let _ = self.release.lock().unwrap().recv();
            typed("PC\\ana", "right")
        }
    }

    /// Audit B18: an operation waits for the Windows dialog at most its
    /// timeout and is then refused, an answer the host gives while the
    /// command line still waits (`ipc::RESPONSE_TIMEOUT`). The dialog used
    /// to have no bound: the command line gave up and said so, and the
    /// operation was applied when the password came. A password typed into
    /// the dialog after the refusal is never checked, so nothing is applied;
    /// until that dialog returns no other opens, and the next operation asks
    /// again.
    #[test]
    fn a_dialog_left_open_past_its_timeout_refuses_and_its_late_password_is_not_checked() {
        use std::time::{Duration, Instant};
        assert!(
            WindowsReAuth::DIALOG_TIMEOUT + Duration::from_secs(20) <= crate::ipc::RESPONSE_TIMEOUT
        );
        let (release, released) = std::sync::mpsc::channel();
        let prompt = std::sync::Arc::new(LeftOpen {
            shown: AtomicUsize::new(0),
            release: std::sync::Mutex::new(released),
        });
        let logon = std::sync::Arc::new(FakeLogon::default());
        let timeout = Duration::from_millis(300);
        let reauth = std::sync::Arc::new(
            WindowsReAuth::with_backends(
                Box::new(std::sync::Arc::clone(&prompt)),
                Box::new(std::sync::Arc::clone(&logon)),
            )
            .with_timeout(timeout),
        );

        let started = Instant::now();
        let (done, answered) = std::sync::mpsc::channel();
        let asking = std::sync::Arc::clone(&reauth);
        std::thread::spawn(move || done.send(asking.reauthenticate("enable")));
        let answer = answered
            .recv_timeout(Duration::from_secs(20))
            .expect("the operation still waits for the dialog past its timeout");
        assert_eq!(answer, Err(ReAuthError::Denied));
        assert!(started.elapsed() >= timeout, "{:?}", started.elapsed());
        assert_eq!(prompt.shown.load(Ordering::SeqCst), 1);

        // The dialog is still on screen: no second one opens.
        match reauth.reauthenticate("resume") {
            Err(ReAuthError::Unavailable(m)) => assert!(m.contains("already open"), "{m}"),
            other => panic!("expected an immediate refusal, got {other:?}"),
        }
        assert_eq!(prompt.shown.load(Ordering::SeqCst), 1);

        // The owner comes back and types the right password: it is wiped
        // unchecked, and the dialog's thread lets go of the dialog.
        release.send(()).unwrap();
        let until = Instant::now() + Duration::from_secs(20);
        while reauth.dialog.try_lock().is_err() {
            assert!(Instant::now() < until, "the late dialog never returned");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            logon.calls.load(Ordering::SeqCst),
            0,
            "a password typed after the refusal was checked"
        );

        // The next operation asks again, and in time the password allows it.
        release.send(()).unwrap();
        assert_eq!(reauth.reauthenticate("enable"), Ok(()));
        assert_eq!(prompt.shown.load(Ordering::SeqCst), 2);
        assert_eq!(logon.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn typed_names_map_to_logon_names() {
        for ((user, domain), want) in [
            (("PC\\ana", ""), ("ana", Some("PC"))),
            (("ana", "PC"), ("ana", Some("PC"))),
            (("ana@example.org", ""), ("ana@example.org", None)),
            (
                ("MicrosoftAccount\\ana@example.org", ""),
                ("ana@example.org", Some("MicrosoftAccount")),
            ),
            (("ana", ""), ("ana", Some("."))),
        ] {
            let (u, d) = logon_names(user, domain);
            assert_eq!((u.as_str(), d.as_deref()), want, "{user:?} {domain:?}");
        }
    }

    /// Every operation the guard names gets wording, the autostart ones say
    /// what they change, and an unknown one gets the strongest wording.
    #[test]
    fn every_guard_operation_has_dialog_wording() {
        for op in [
            "create_grant",
            "set_password",
            "reg_start",
            "master_on",
            "enable",
            "resume",
            "unlock",
            "set_settings",
            "set_options",
            "service_install",
            "service_install_elevated",
            "service_uninstall",
            "backup_export",
            "backup_import",
            "identity_view",
            "settings_change",
            "install",
            "uninstall",
        ] {
            assert!(!purpose_of(op).is_empty(), "{op}");
        }
        // §B.1.1: the install's dialog says what it changes.
        assert_eq!(purpose_of("install"), "install Tornect on this computer");
        assert_eq!(purpose_of("uninstall"), "remove Tornect from this computer");
        // Slice-F F1-3: the dialog of the elevated install says what it means
        // (§B.8.7.5's copy), and no other dialog says it.
        let elevated = purpose_of("service_install_elevated");
        assert!(
            elevated.contains("ELEVATED") && elevated.contains("administrator session"),
            "{elevated}"
        );
        assert!(!purpose_of("service_install").contains("administrator"));
        assert_eq!(
            purpose_of("service_uninstall"),
            "change what starts when you log in"
        );
        assert_eq!(
            purpose_of("some_future_operation"),
            purpose_of("create_grant")
        );
    }

    /// The password never reaches `Debug`, and it is NUL-terminated for
    /// `LogonUserW` however the prompt returned it.
    #[test]
    fn a_prompted_credential_redacts_and_terminates_its_password() {
        let c = PromptedCredential::new(
            "PC\\ana".to_owned(),
            String::new(),
            zeroize::Zeroizing::new("hunter2".encode_utf16().collect()),
        );
        let shown = format!("{c:?}");
        assert!(
            !shown.contains("hunter2") && !shown.contains("ana"),
            "{shown}"
        );
        assert_eq!(c.password_wide().last(), Some(&0));
    }

    /// The banner's acknowledgement asks with its own purpose (§B.8.6.2): what
    /// it confirms, not a change of a security setting.
    #[test]
    fn the_acknowledgement_names_its_own_purpose() {
        assert_eq!(
            purpose_of("acknowledge_banner"),
            "confirm that you have seen which devices can connect without asking"
        );
        assert_ne!(
            purpose_of("acknowledge_banner"),
            purpose_of("settings_change")
        );
    }

    /// On Linux the acknowledgement asks through the settings action, whose
    /// message the policy file keeps as it is.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_acknowledgement_maps_to_the_settings_action() {
        assert_eq!(
            PolkitReAuth::new().action_for("acknowledge_banner"),
            "org.tornect.settings"
        );
    }
}
