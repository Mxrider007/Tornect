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
/// 2026-09-04 against polkitd 127 on mx-vm; full record in the research note
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
            // Changes what runs at login.
            "service_install" | "service_uninstall" => "autostart",
            // Moves secrets out of the store.
            "backup_export" | "backup_import" | "identity_view" => "export",
            // Policy and settings.
            "set_settings" | "set_options" | "settings_change" => "settings",
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

        let reply = reply.map_err(|e| {
            let text = e.to_string();
            if text.contains("is not registered") {
                // Not a denial. The host has no policy file, so no dialog can
                // ever be raised — reporting `Denied` would tell the operator
                // they typed the wrong password.
                ReAuthError::Unavailable(format!(
                    "polkit action `{action_id}` is not registered on this host — install \
                     packaging/polkit/org.tornect.policy into /usr/share/polkit-1/actions/ \
                     and restart polkit ({text})"
                ))
            } else {
                ReAuthError::Failed(text)
            }
        })?;

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
            "service_uninstall",
            "backup_export",
            "backup_import",
            "identity_view",
            "settings_change",
        ] {
            let action = p.action_for(op);
            assert!(
                registered.contains(&action.as_str()),
                "op `{op}` maps to `{action}`, which the policy file does not declare"
            );
        }
        assert_eq!(
            p.action_for("some_future_operation"),
            "org.tornect.grant",
            "an unknown operation must get the strongest wording, not the mildest"
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
}
