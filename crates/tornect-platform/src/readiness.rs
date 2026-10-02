//! The readiness probes of §B.8.7.1 ⑥ (`docs/PLAN.md`): the rows of
//! [`ReadinessSnapshot`] that this crate can read honestly, from facts read at
//! host start and every [`REPROBE_EVERY`] (`tornect_core::unattended::readiness`).
//! A row this build cannot read stays `Unknown`, which never blocks and raises
//! the badge (§B.8.14): the copy claims only what a probe confirmed.
//!
//! [`rows`] is the decision, from [`Facts`] (tested everywhere); [`facts_now`]
//! reads them from this computer.
//!
//! [`REPROBE_EVERY`]: tornect_core::unattended::readiness::REPROBE_EVERY

use std::path::Path;

use tornect_core::levels::HelperPresence;
use tornect_core::unattended::readiness::{Probe, ReadinessSnapshot};

use crate::hotkey::KeyState;

/// What the probes read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    /// The desktop is Wayland, where the screen-sharing portal decides capture
    /// and input.
    pub wayland: bool,
    /// A screen-sharing grant is kept (the portal's restore token).
    pub restore_token: bool,
    /// The store's keystore is the file one (no OS keychain).
    pub file_keystore: bool,
    /// Automatic sign-in at boot: `None` where it cannot be read here.
    pub auto_login: Option<bool>,
    /// The panic key.
    pub panic_key: KeyState,
    /// The window host is running, which shows the indicator; `false` for the
    /// terminal host.
    pub window: bool,
    /// Some grant holds the administrator level (Windows).
    pub admin_grant: bool,
    /// The administrator helper task (Windows).
    pub helper: HelperPresence,
}

/// The rows these facts give; the others stay `Unknown`.
#[must_use]
pub fn rows(facts: &Facts) -> ReadinessSnapshot {
    let mut snap = ReadinessSnapshot::unknown();
    // Capture and input: on Wayland the portal asks once and the grant is kept;
    // elsewhere (X11, Windows) no permission is needed. A missing grant is a
    // warning, never a refusal (`HOST_NOT_READY` is for a capture that cannot
    // work).
    let (capture, input) = if facts.wayland && !facts.restore_token {
        let why = "no screen-sharing grant is kept yet: the desktop asks once, at the first \
                   session, and someone must answer it"
            .to_owned();
        (Probe::Warn(why.clone()), Probe::Warn(why))
    } else {
        (Probe::Ok, Probe::Ok)
    };
    snap.capture = capture;
    snap.input = input;
    snap.auto_login = match facts.auto_login {
        Some(true) => Probe::Ok,
        Some(false) => Probe::Warn(
            "automatic sign-in is off: after a restart nobody is signed in, so this computer \
             cannot be reached until someone signs in (Tornect never turns it on)"
                .to_owned(),
        ),
        None => Probe::Unknown,
    };
    snap.keystore = if facts.file_keystore {
        Probe::Warn(
            "the keys are kept in a file, not in the system's keychain: passwords must be \
             stronger (or generated)"
                .to_owned(),
        )
    } else {
        Probe::Ok
    };
    snap.panic_key = match facts.panic_key {
        KeyState::Bound => Probe::Ok,
        state @ (KeyState::NotTried | KeyState::Unavailable) => Probe::Fail(state.row().to_owned()),
    };
    snap.consent_indicator = if facts.window {
        Probe::Ok
    } else {
        Probe::Warn(
            "no window: the sharing indicator is this terminal's lines, not a window on top"
                .to_owned(),
        )
    };
    snap.admin_helper = match (facts.admin_grant, facts.helper) {
        (false, _) => Probe::Ok,
        (true, HelperPresence::Registered) => Probe::Ok,
        (true, HelperPresence::Absent) => Probe::Fail(
            "administrator helper not registered: unattended sessions at the administrator \
             level start without it"
                .to_owned(),
        ),
        (true, HelperPresence::Unreadable) => Probe::Warn(
            "whether the administrator helper is registered could not be read".to_owned(),
        ),
    };
    snap
}

/// Read the facts of this computer for a host whose home is `state_dir`.
#[must_use]
pub fn facts_now(
    state_dir: &Path,
    restore_token: &Path,
    file_keystore: bool,
    window: bool,
    admin_grant: bool,
) -> Facts {
    let _ = state_dir;
    Facts {
        wayland: wayland(),
        restore_token: restore_token.exists(),
        file_keystore,
        auto_login: auto_login(),
        panic_key: crate::hotkey::state(),
        window,
        admin_grant,
        helper: if admin_grant {
            crate::helper_task::presence_now()
        } else {
            HelperPresence::Absent
        },
    }
}

/// Whether this session's desktop is Wayland.
fn wayland() -> bool {
    cfg!(target_os = "linux")
        && (std::env::var_os("WAYLAND_DISPLAY").is_some()
            || std::env::var("XDG_SESSION_TYPE").is_ok_and(|t| t == "wayland"))
}

/// GDM's automatic sign-in (`/etc/gdm3/custom.conf` or `/etc/gdm/custom.conf`,
/// `[daemon] AutomaticLoginEnable`); `None` elsewhere or when it cannot be read.
fn auto_login() -> Option<bool> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    ["/etc/gdm3/custom.conf", "/etc/gdm/custom.conf"]
        .iter()
        .find_map(|path| std::fs::read_to_string(path).ok())
        .map(|text| gdm_auto_login(&text))
}

/// `AutomaticLoginEnable` of GDM's `[daemon]` section: on only when `true`.
fn gdm_auto_login(text: &str) -> bool {
    let mut daemon = false;
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            daemon = line.eq_ignore_ascii_case("[daemon]");
        } else if daemon
            && let Some((key, value)) = line.split_once('=')
            && key.trim() == "AutomaticLoginEnable"
        {
            return value.trim().eq_ignore_ascii_case("true");
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> Facts {
        Facts {
            wayland: false,
            restore_token: false,
            file_keystore: false,
            auto_login: Some(true),
            panic_key: KeyState::Bound,
            window: true,
            admin_grant: false,
            helper: HelperPresence::Absent,
        }
    }

    /// The probes' logic on fakes: each fact gives its row; no row these
    /// probes read ever gives `HOST_NOT_READY`, whose causes are a capture or
    /// input that cannot work, the lock and another user on the console
    /// (§B.8.14), which stay `Unknown` here.
    #[test]
    fn probe_rows_follow_the_facts_and_never_refuse_a_session() {
        let ok = rows(&facts());
        assert_eq!(ok.capture, Probe::Ok);
        assert_eq!(ok.input, Probe::Ok);
        assert_eq!(ok.auto_login, Probe::Ok);
        assert_eq!(ok.keystore, Probe::Ok);
        assert_eq!(ok.panic_key, Probe::Ok);
        assert_eq!(ok.consent_indicator, Probe::Ok);
        assert_eq!(ok.admin_helper, Probe::Ok);
        for unread in [
            &ok.os_password,
            &ok.idle_lock,
            &ok.lock_state,
            &ok.console_owner,
            &ok.tor_self_connect,
        ] {
            assert_eq!(*unread, Probe::Unknown);
        }

        let mut f = facts();
        f.wayland = true;
        assert!(
            matches!(rows(&f).capture, Probe::Warn(_)),
            "no grant kept yet"
        );
        assert!(matches!(rows(&f).input, Probe::Warn(_)));
        f.restore_token = true;
        assert_eq!(rows(&f).capture, Probe::Ok);

        let mut f = facts();
        f.auto_login = Some(false);
        assert!(matches!(rows(&f).auto_login, Probe::Warn(_)));
        f.auto_login = None;
        assert_eq!(rows(&f).auto_login, Probe::Unknown);
        f.file_keystore = true;
        assert!(matches!(rows(&f).keystore, Probe::Warn(_)));
        f.panic_key = KeyState::Unavailable;
        assert_eq!(
            rows(&f).panic_key,
            Probe::Fail("Panic key: unavailable".to_owned())
        );
        f.window = false;
        assert!(matches!(rows(&f).consent_indicator, Probe::Warn(_)));
        // The administrator helper, only while an admin grant exists.
        f.helper = HelperPresence::Absent;
        assert_eq!(rows(&f).admin_helper, Probe::Ok);
        f.admin_grant = true;
        assert!(matches!(rows(&f).admin_helper, Probe::Fail(_)));
        f.helper = HelperPresence::Unreadable;
        assert!(matches!(rows(&f).admin_helper, Probe::Warn(_)));
        f.helper = HelperPresence::Registered;
        assert_eq!(rows(&f).admin_helper, Probe::Ok);

        // Every combination: none of these rows refuses a session.
        for wayland in [false, true] {
            for token in [false, true] {
                for panic_key in [KeyState::NotTried, KeyState::Bound, KeyState::Unavailable] {
                    for helper in [
                        HelperPresence::Absent,
                        HelperPresence::Registered,
                        HelperPresence::Unreadable,
                    ] {
                        let snap = rows(&Facts {
                            wayland,
                            restore_token: token,
                            file_keystore: true,
                            auto_login: Some(false),
                            panic_key,
                            window: false,
                            admin_grant: true,
                            helper,
                        });
                        assert_eq!(snap.host_not_ready_cause(), None);
                    }
                }
            }
        }
    }

    /// GDM's automatic sign-in: on only in `[daemon]` with `true`.
    #[test]
    fn gdm_auto_login_is_read_from_its_daemon_section() {
        assert!(gdm_auto_login(
            "[daemon]\nAutomaticLoginEnable = True\nAutomaticLogin=a\n"
        ));
        assert!(!gdm_auto_login("[daemon]\n#AutomaticLoginEnable=true\n"));
        assert!(!gdm_auto_login("[security]\nAutomaticLoginEnable=true\n"));
        assert!(!gdm_auto_login("[daemon]\nAutomaticLoginEnable=false\n"));
        assert!(!gdm_auto_login(""));
    }
}
