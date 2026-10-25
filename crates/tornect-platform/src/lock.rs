//! Whether this computer is locked, as the session services need it (design
//! `services` §2.3, `docs/PLAN.md` §B.8.8; `docs/research/services.md` R3).
//!
//! While the host is locked or shows a secure screen, files and the clipboard
//! pause: they would otherwise reach past the OS lock. The host reads the
//! state about once a second while a services stream is open:
//!
//! - **Linux** ([`LockedHint`]): logind's `Session.LockedHint` of the session
//!   whose screen locker guards the shared desktop (the process's own
//!   graphical session, or else the user's display session). GNOME and KDE
//!   set it; xscreensaver, xss-lock and swaylock do not, so under those the
//!   services never pause (a stated residual, R3.2). GNOME Wayland is covered
//!   anyway: mutter ends the remote-desktop session on lock, so capture and
//!   with it the services stop.
//! - **Windows** (`locked_now`): whether a secure screen is the input
//!   desktop (`OpenInputDesktop`): the lock screen, Ctrl+Alt+Del and UAC
//!   prompts.
//!
//! [`LockWatch`] turns readings into changes: a host starts unlocked, and a
//! reading that could not be taken (`None`) never changes the state, so a
//! host whose logind cannot be read keeps its files rather than losing them
//! for good (the design's §14).

/// Readings in, changes out (design §2.3): `Some(true)` once when the host
/// locks, `Some(false)` once when it unlocks; an unreadable reading changes
/// nothing. It starts unlocked.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LockWatch {
    locked: bool,
}

impl LockWatch {
    /// An unlocked host.
    #[must_use]
    pub const fn new() -> Self {
        Self { locked: false }
    }

    /// Whether the host is taken to be locked now.
    #[must_use]
    pub const fn locked(&self) -> bool {
        self.locked
    }

    /// The change `reading` makes, if any.
    pub fn read(&mut self, reading: Option<bool>) -> Option<bool> {
        match reading {
            Some(now) if now != self.locked => {
                self.locked = now;
                Some(now)
            }
            _ => None,
        }
    }
}

/// How long one reading of logind may take; a slower answer is no reading.
#[cfg(target_os = "linux")]
const READ_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// logind's `LockedHint` of the session whose screen locker guards the
/// desktop this host shares (R3.1).
#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
pub struct LockedHint {
    conn: zbus::Connection,
    session: zbus::zvariant::OwnedObjectPath,
}

#[cfg(target_os = "linux")]
impl LockedHint {
    /// Connect to the system bus and find the session: this process's own
    /// when it is graphical, else the user's display session. `None` when
    /// the bus, logind or a session cannot be had (said at debug: the host
    /// then never pauses its services for a lock, as with a locker that sets
    /// no hint).
    pub async fn connect() -> Option<Self> {
        let conn = match tokio::time::timeout(READ_WAIT, zbus::Connection::system()).await {
            Ok(Ok(conn)) => conn,
            Ok(Err(e)) => {
                tracing::debug!(error = %e, "the lock probe has no system D-Bus");
                return None;
            }
            Err(_) => {
                tracing::debug!("the lock probe's system D-Bus did not answer");
                return None;
            }
        };
        let found = tokio::time::timeout(
            READ_WAIT,
            crate::logind::desktop_session(&conn, std::process::id(), crate::logind::this_uid),
        )
        .await;
        match found {
            Ok(Ok(session)) => Some(Self { conn, session }),
            Ok(Err(e)) => {
                tracing::debug!(error = %e, "the lock probe found no session to read");
                None
            }
            Err(_) => {
                tracing::debug!("logind did not say which session to read the lock of");
                None
            }
        }
    }

    /// The session's `LockedHint` now; `None` when it could not be read
    /// within 2 s or is not a boolean.
    pub async fn read(&self) -> Option<bool> {
        read_hint(&self.conn, self.session.as_str()).await
    }

    /// The logind object path of the session read.
    #[must_use]
    pub fn session(&self) -> &str {
        self.session.as_str()
    }
}

/// `LockedHint` of the session `path`, bounded by [`READ_WAIT`].
#[cfg(target_os = "linux")]
pub(crate) async fn read_hint(bus: &impl crate::logind::Logind, path: &str) -> Option<bool> {
    let value = tokio::time::timeout(
        READ_WAIT,
        bus.property(path, crate::logind::SESSION, "LockedHint"),
    )
    .await;
    match value {
        Ok(Ok(value)) => crate::logind::boolean(&value),
        Ok(Err(e)) => {
            tracing::debug!(error = %e, "the lock state could not be read");
            None
        }
        Err(_) => {
            tracing::debug!("logind did not say the lock state in time");
            None
        }
    }
}

/// Whether a secure Windows screen (the lock screen, Ctrl+Alt+Del, a UAC
/// prompt) is the input desktop now; `None` when unreadable
/// (NEEDS-DEVICE(windows)).
#[cfg(windows)]
#[must_use]
pub fn locked_now() -> Option<bool> {
    crate::helper::secure_desktop_shown()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The host starts unlocked; each reading that differs is one change;
    /// a reading that could not be taken keeps the last state, locked or
    /// not.
    #[test]
    fn readings_change_the_state_only_when_they_differ() {
        let mut watch = LockWatch::new();
        assert!(!watch.locked());
        assert_eq!(watch.read(None), None);
        assert_eq!(watch.read(Some(false)), None);
        assert_eq!(watch.read(Some(true)), Some(true));
        assert!(watch.locked());
        assert_eq!(watch.read(Some(true)), None);
        assert_eq!(watch.read(None), None, "an unreadable probe unlocked");
        assert!(watch.locked());
        assert_eq!(watch.read(Some(false)), Some(false));
        assert_eq!(watch.read(None), None, "an unreadable probe locked");
        assert!(!watch.locked());
        assert_eq!(LockWatch::default(), LockWatch::new());
    }

    /// The hint is read from the session found, as a boolean; anything
    /// else, an error or no answer in time, is no reading.
    #[cfg(target_os = "linux")]
    #[tokio::test(start_paused = true)]
    async fn the_hint_is_read_from_the_session_or_is_no_reading() {
        use crate::logind::BoxFuture;
        use crate::logind::tests::{FakeLogind, owned};
        use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

        const SESSION: &str = "/org/freedesktop/login1/session/_31";
        let bus = FakeLogind::default();
        bus.set(SESSION, "LockedHint", Ok(owned(Value::from(true))));
        assert_eq!(read_hint(&bus, SESSION).await, Some(true));
        bus.set(SESSION, "LockedHint", Ok(owned(Value::from(false))));
        assert_eq!(read_hint(&bus, SESSION).await, Some(false));
        bus.set(SESSION, "LockedHint", Ok(owned(Value::from("yes"))));
        assert_eq!(read_hint(&bus, SESSION).await, None);
        bus.set(
            SESSION,
            "LockedHint",
            Err("logind Session.LockedHint: unknown object".to_owned()),
        );
        assert_eq!(read_hint(&bus, SESSION).await, None);
        assert!(
            bus.reads
                .lock()
                .unwrap()
                .iter()
                .all(|(path, name)| path == SESSION && name == "LockedHint"),
            "another property or session was read"
        );

        /// A logind that never answers.
        struct Stuck;
        impl crate::logind::Logind for Stuck {
            fn session_by_pid(&self, _: u32) -> BoxFuture<'_, Option<OwnedObjectPath>> {
                Box::pin(std::future::pending())
            }
            fn user(&self, _: u32) -> BoxFuture<'_, Result<OwnedObjectPath, String>> {
                Box::pin(std::future::pending())
            }
            fn property<'a>(
                &'a self,
                _: &'a str,
                _: &'a str,
                _: &'a str,
            ) -> BoxFuture<'a, Result<OwnedValue, String>> {
                Box::pin(std::future::pending())
            }
        }
        let before = tokio::time::Instant::now();
        assert_eq!(read_hint(&Stuck, SESSION).await, None);
        assert_eq!(tokio::time::Instant::now() - before, READ_WAIT);
    }

    /// This machine's logind: the session found and its hint read (false
    /// while the desktop is in use). Talks to the system D-Bus, so it is run
    /// by hand, unlocked and then with the screen locked from another
    /// terminal (`sleep 5; loginctl lock-session`, or Super+L while a
    /// `sleep 10` runs first): `cargo test -p tornect-platform --lib --
    /// --ignored live_locked_hint --nocapture`.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "talks to this machine's logind over the system D-Bus"]
    #[allow(clippy::print_stderr)] // the live test reports what it read
    async fn live_locked_hint() {
        let probe = LockedHint::connect()
            .await
            .expect("the system bus and a session to read");
        let mut watch = LockWatch::new();
        for second in 0..20 {
            let reading = probe.read().await;
            let changed = watch.read(reading);
            eprintln!(
                "{second:>2} s: LockedHint of {} = {reading:?} (change: {changed:?})",
                probe.session()
            );
            assert!(reading.is_some(), "the hint could not be read");
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }
}
