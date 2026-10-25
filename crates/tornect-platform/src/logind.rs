//! logind on the system D-Bus, as far as this crate asks it: which session
//! this process belongs to, and a property of that session. The polkit
//! revocation ([`crate::polkit`]) and the lock probe ([`crate::lock`]) share
//! it (design `services` §8; `docs/research/services.md` R3).
//!
//! The calls go through [`Logind`], which the system bus's connection
//! implements and the tests fake, so the lookups are tested without a bus.
//!
//! Two lookups, for two needs:
//! - [`session_id`] (polkit's subject): logind's session of this process
//!   (`GetSessionByPID`), or else the user's display session (`User.Display`),
//!   which is what `pkcheck --revoke-temp` resolves outside a session and what
//!   logind's own `session/auto` names;
//! - [`desktop_session`] (the lock): the same, except that the process's own
//!   session counts only when it is graphical (`Type` `x11`, `wayland` or
//!   `mir`). A host started from an SSH login sits in a `tty` session whose
//!   `LockedHint` no screen locker ever sets; the desktop it shares is the
//!   user's display session, whose locker does (R3.1).

use std::future::Future;
use std::pin::Pin;

use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

/// A boxed future, as the other seams of this crate take them.
pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub(crate) const LOGIN: &str = "org.freedesktop.login1";
const MANAGER_PATH: &str = "/org/freedesktop/login1";
const MANAGER: &str = "org.freedesktop.login1.Manager";
/// The interface of a session object.
pub(crate) const SESSION: &str = "org.freedesktop.login1.Session";
/// The interface of a user object.
const USER: &str = "org.freedesktop.login1.User";

/// The session types a screen locker runs in (`sd_session_get_type`).
const GRAPHICAL: [&str; 3] = ["x11", "wayland", "mir"];

/// What this crate asks logind. Errors are messages for the log; they never
/// carry anything but logind's own words.
pub(crate) trait Logind: Send + Sync {
    /// `Manager.GetSessionByPID(pid)`: the session `pid` belongs to; `None`
    /// when it belongs to none or logind cannot say.
    fn session_by_pid(&self, pid: u32) -> BoxFuture<'_, Option<OwnedObjectPath>>;

    /// `Manager.GetUser(uid)`: the user object of `uid`.
    fn user(&self, uid: u32) -> BoxFuture<'_, Result<OwnedObjectPath, String>>;

    /// `org.freedesktop.DBus.Properties.Get(iface, name)` of logind object
    /// `path`.
    fn property<'a>(
        &'a self,
        path: &'a str,
        iface: &'a str,
        name: &'a str,
    ) -> BoxFuture<'a, Result<OwnedValue, String>>;
}

impl Logind for zbus::Connection {
    fn session_by_pid(&self, pid: u32) -> BoxFuture<'_, Option<OwnedObjectPath>> {
        Box::pin(async move {
            let reply = self
                .call_method(
                    Some(LOGIN),
                    MANAGER_PATH,
                    Some(MANAGER),
                    "GetSessionByPID",
                    &(pid,),
                )
                .await
                .ok()?;
            reply.body().deserialize::<OwnedObjectPath>().ok()
        })
    }

    fn user(&self, uid: u32) -> BoxFuture<'_, Result<OwnedObjectPath, String>> {
        Box::pin(async move {
            self.call_method(Some(LOGIN), MANAGER_PATH, Some(MANAGER), "GetUser", &(uid,))
                .await
                .map_err(|e| format!("logind GetUser: {e}"))?
                .body()
                .deserialize::<OwnedObjectPath>()
                .map_err(|e| format!("logind GetUser: {e}"))
        })
    }

    fn property<'a>(
        &'a self,
        path: &'a str,
        iface: &'a str,
        name: &'a str,
    ) -> BoxFuture<'a, Result<OwnedValue, String>> {
        Box::pin(async move {
            let reply = self
                .call_method(
                    Some(LOGIN),
                    path,
                    Some("org.freedesktop.DBus.Properties"),
                    "Get",
                    &(iface, name),
                )
                .await
                .map_err(|e| format!("logind {iface}.{name}: {e}"))?;
            reply
                .body()
                .deserialize::<OwnedValue>()
                .map_err(|e| format!("logind {iface}.{name}: {e}"))
        })
    }
}

/// The string inside a property value (a variant of `s`, or a structure
/// whose first field is one, as `User.Display`'s `(so)`).
pub(crate) fn first_str(value: &Value<'_>) -> Option<String> {
    match value {
        Value::Str(s) => Some(s.to_string()),
        Value::Value(inner) => first_str(inner),
        Value::Structure(st) => st.fields().first().and_then(first_str),
        _ => None,
    }
}

/// The object path inside a property value (a variant of `o`, or a structure
/// that holds one, as `User.Display`'s `(so)`).
fn object_path(value: &Value<'_>) -> Option<OwnedObjectPath> {
    match value {
        Value::ObjectPath(path) => Some(OwnedObjectPath::from(path.to_owned())),
        Value::Value(inner) => object_path(inner),
        Value::Structure(st) => st.fields().iter().find_map(object_path),
        _ => None,
    }
}

/// The boolean inside a property value; `None` for anything else.
pub(crate) fn boolean(value: &Value<'_>) -> Option<bool> {
    match value {
        Value::Bool(b) => Some(*b),
        Value::Value(inner) => boolean(inner),
        _ => None,
    }
}

/// This process's user id, as the kernel says it (`/proc/self`'s owner),
/// never from the environment.
pub(crate) fn this_uid() -> Result<u32, String> {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::metadata("/proc/self")
        .map(|m| m.uid())
        .map_err(|e| format!("reading this process's uid: {e}"))
}

/// The id of the session polkit's subject names: logind's session of `pid`,
/// or else the display session of the user `uid` (read only then).
pub(crate) async fn session_id(
    bus: &impl Logind,
    pid: u32,
    uid: impl FnOnce() -> Result<u32, String>,
) -> Result<String, String> {
    if let Some(path) = bus.session_by_pid(pid).await {
        let id = bus.property(path.as_str(), SESSION, "Id").await?;
        return first_str(&id)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| "logind gave no session id".to_owned());
    }
    // Outside a session (a user service, a terminal of no session): the
    // user's display session, as polkit itself falls back to.
    let display = display(bus, uid()?).await?;
    first_str(&display)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| "this user has no session to revoke approvals in".to_owned())
}

/// The object path of the session whose screen locker guards the desktop this
/// process shares: logind's session of `pid` when it is graphical, or else
/// the display session of the user `uid` (read only then).
pub(crate) async fn desktop_session(
    bus: &impl Logind,
    pid: u32,
    uid: impl FnOnce() -> Result<u32, String>,
) -> Result<OwnedObjectPath, String> {
    if let Some(path) = bus.session_by_pid(pid).await {
        let kind = bus.property(path.as_str(), SESSION, "Type").await?;
        if first_str(&kind).is_some_and(|kind| GRAPHICAL.contains(&kind.as_str())) {
            return Ok(path);
        }
    }
    let display = display(bus, uid()?).await?;
    // A user without a display session has `("", "/")`.
    object_path(&display)
        .filter(|path| first_str(&display).is_some_and(|id| !id.is_empty()) && path.as_str() != "/")
        .ok_or_else(|| "this user has no display session".to_owned())
}

/// `User.Display` of the user `uid`: `(so)`, the display session's id and
/// object path.
async fn display(bus: &impl Logind, uid: u32) -> Result<OwnedValue, String> {
    let user = bus.user(uid).await?;
    bus.property(user.as_str(), USER, "Display").await
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use zbus::zvariant::ObjectPath;

    use super::*;

    /// A fake logind: sessions by pid, users by uid, and properties by
    /// object path; every property read is counted.
    #[derive(Default)]
    pub(crate) struct FakeLogind {
        pub(crate) by_pid: HashMap<u32, String>,
        pub(crate) users: HashMap<u32, String>,
        pub(crate) properties: Mutex<HashMap<(String, String), Result<OwnedValue, String>>>,
        pub(crate) reads: Mutex<Vec<(String, String)>>,
    }

    impl FakeLogind {
        pub(crate) fn set(&self, path: &str, name: &str, value: Result<OwnedValue, String>) {
            self.properties
                .lock()
                .unwrap()
                .insert((path.to_owned(), name.to_owned()), value);
        }
    }

    pub(crate) fn owned(value: Value<'_>) -> OwnedValue {
        OwnedValue::try_from(value).unwrap()
    }

    fn path(p: &str) -> OwnedObjectPath {
        OwnedObjectPath::try_from(p).unwrap()
    }

    /// `User.Display`'s `(so)`.
    pub(crate) fn display_value(id: &str, p: &str) -> OwnedValue {
        owned(Value::from((id, ObjectPath::try_from(p).unwrap())))
    }

    impl Logind for FakeLogind {
        fn session_by_pid(&self, pid: u32) -> BoxFuture<'_, Option<OwnedObjectPath>> {
            let found = self.by_pid.get(&pid).map(|p| path(p));
            Box::pin(async move { found })
        }

        fn user(&self, uid: u32) -> BoxFuture<'_, Result<OwnedObjectPath, String>> {
            let found = self
                .users
                .get(&uid)
                .map(|p| path(p))
                .ok_or_else(|| format!("logind GetUser: no user {uid}"));
            Box::pin(async move { found })
        }

        fn property<'a>(
            &'a self,
            path: &'a str,
            iface: &'a str,
            name: &'a str,
        ) -> BoxFuture<'a, Result<OwnedValue, String>> {
            self.reads
                .lock()
                .unwrap()
                .push((path.to_owned(), name.to_owned()));
            let value = self
                .properties
                .lock()
                .unwrap()
                .get(&(path.to_owned(), name.to_owned()))
                .map(|v| match v {
                    Ok(v) => v.try_clone().map_err(|e| e.to_string()),
                    Err(e) => Err(e.clone()),
                })
                .unwrap_or_else(|| Err(format!("logind {iface}.{name}: no such property")));
            Box::pin(async move { value })
        }
    }

    const PID: u32 = 4242;
    const UID: u32 = 1000;
    const OWN: &str = "/org/freedesktop/login1/session/_32";
    const DESK: &str = "/org/freedesktop/login1/session/_31";
    const USER_PATH: &str = "/org/freedesktop/login1/user/_1000";

    fn uid() -> Result<u32, String> {
        Ok(UID)
    }

    fn not_asked() -> Result<u32, String> {
        panic!("the user was looked up although the process has its session")
    }

    fn bus(own_type: Option<&str>) -> FakeLogind {
        let mut bus = FakeLogind::default();
        if let Some(kind) = own_type {
            bus.by_pid.insert(PID, OWN.to_owned());
            bus.set(OWN, "Type", Ok(owned(Value::from(kind))));
            bus.set(OWN, "Id", Ok(owned(Value::from("2"))));
        }
        bus.users.insert(UID, USER_PATH.to_owned());
        bus.set(USER_PATH, "Display", Ok(display_value("1", DESK)));
        bus
    }

    /// polkit's subject is the process's own session whatever its type, and
    /// the user's display session only outside any session: the lookup it
    /// made before the move to this module.
    #[tokio::test]
    async fn polkit_names_the_processs_own_session_else_the_display_session() {
        for kind in ["wayland", "tty"] {
            assert_eq!(
                session_id(&bus(Some(kind)), PID, not_asked).await,
                Ok("2".to_owned()),
                "{kind}"
            );
        }
        assert_eq!(session_id(&bus(None), PID, uid).await, Ok("1".to_owned()));
        // A session whose id is empty, and a user with no display session.
        let empty = bus(Some("x11"));
        empty.set(OWN, "Id", Ok(owned(Value::from(""))));
        assert_eq!(
            session_id(&empty, PID, not_asked).await,
            Err("logind gave no session id".to_owned())
        );
        let none = bus(None);
        none.set(USER_PATH, "Display", Ok(display_value("", "/")));
        assert_eq!(
            session_id(&none, PID, uid).await,
            Err("this user has no session to revoke approvals in".to_owned())
        );
        // The uid is asked only for the fallback, and its failure said.
        assert_eq!(
            session_id(&bus(None), PID, || Err("no /proc".to_owned())).await,
            Err("no /proc".to_owned())
        );
    }

    /// The lock reads the session whose locker guards the desktop: the
    /// process's own when it is graphical, the user's display session when
    /// it is a `tty` (an SSH login) or when there is none (the systemd user
    /// unit).
    #[tokio::test]
    async fn the_lock_reads_the_graphical_session() {
        for kind in ["x11", "wayland", "mir"] {
            assert_eq!(
                desktop_session(&bus(Some(kind)), PID, not_asked).await,
                Ok(path(OWN)),
                "{kind}"
            );
        }
        for kind in ["tty", "unspecified", ""] {
            assert_eq!(
                desktop_session(&bus(Some(kind)), PID, uid).await,
                Ok(path(DESK)),
                "{kind}"
            );
        }
        assert_eq!(desktop_session(&bus(None), PID, uid).await, Ok(path(DESK)));
        let none = bus(None);
        none.set(USER_PATH, "Display", Ok(display_value("", "/")));
        assert_eq!(
            desktop_session(&none, PID, uid).await,
            Err("this user has no display session".to_owned())
        );
        // A `Type` that cannot be read is an error, not a guess.
        let unread = bus(Some("wayland"));
        unread.set(OWN, "Type", Err("logind Session.Type: timeout".to_owned()));
        assert_eq!(
            desktop_session(&unread, PID, uid).await,
            Err("logind Session.Type: timeout".to_owned())
        );
    }

    /// Values are taken out of their variants; anything else is no answer.
    #[test]
    fn values_are_read_out_of_their_variants() {
        assert_eq!(boolean(&Value::from(true)), Some(true));
        assert_eq!(
            boolean(&Value::Value(Box::new(Value::from(false)))),
            Some(false)
        );
        assert_eq!(boolean(&Value::from("true")), None);
        assert_eq!(boolean(&Value::from(1u32)), None);
        let display = display_value("c2", "/org/freedesktop/login1/session/c2");
        assert_eq!(first_str(&display), Some("c2".to_owned()));
        assert_eq!(
            object_path(&display),
            Some(path("/org/freedesktop/login1/session/c2"))
        );
        assert_eq!(object_path(&Value::from("not a path")), None);
    }

    /// logind on a D-Bus of its own (a private `dbus-daemon`, as the
    /// capture crate's fake portal): the real calls of [`Logind`] for
    /// `zbus::Connection`, through the lookups and the lock's read. It
    /// starts a `dbus-daemon`, so it is run by hand:
    /// `cargo test -p tornect-platform --lib -- --ignored fake_bus`.
    mod fake_bus {
        use std::io::{BufRead as _, BufReader};
        use std::process::{Command, Stdio};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        use zbus::interface;
        use zbus::zvariant::OwnedObjectPath;

        use super::super::*;

        const OWN: &str = "/org/freedesktop/login1/session/_32";
        const DESK: &str = "/org/freedesktop/login1/session/_31";
        const USER_PATH: &str = "/org/freedesktop/login1/user/_1000";
        /// The pid the fake puts in the session `OWN`; any other is in none.
        const IN_SESSION: u32 = 4242;

        struct Manager;

        #[interface(name = "org.freedesktop.login1.Manager")]
        impl Manager {
            #[zbus(name = "GetSessionByPID")]
            fn get_session_by_pid(&self, pid: u32) -> zbus::fdo::Result<OwnedObjectPath> {
                if pid == IN_SESSION {
                    Ok(OwnedObjectPath::try_from(OWN).unwrap())
                } else {
                    Err(zbus::fdo::Error::Failed(format!(
                        "PID {pid} does not belong to any known session"
                    )))
                }
            }

            fn get_user(&self, uid: u32) -> zbus::fdo::Result<OwnedObjectPath> {
                if uid == 1000 {
                    Ok(OwnedObjectPath::try_from(USER_PATH).unwrap())
                } else {
                    Err(zbus::fdo::Error::Failed(format!("no user {uid}")))
                }
            }
        }

        struct Session {
            id: &'static str,
            kind: &'static str,
            locked: Arc<AtomicBool>,
        }

        #[interface(name = "org.freedesktop.login1.Session")]
        impl Session {
            #[zbus(property)]
            fn id(&self) -> String {
                self.id.to_owned()
            }

            #[zbus(property, name = "Type")]
            fn kind(&self) -> String {
                self.kind.to_owned()
            }

            #[zbus(property)]
            fn locked_hint(&self) -> bool {
                self.locked.load(Ordering::SeqCst)
            }
        }

        struct User;

        #[interface(name = "org.freedesktop.login1.User")]
        impl User {
            #[zbus(property)]
            fn display(&self) -> (String, OwnedObjectPath) {
                ("31".to_owned(), OwnedObjectPath::try_from(DESK).unwrap())
            }
        }

        #[tokio::test]
        #[ignore = "starts a dbus-daemon: cargo test -p tornect-platform --lib -- --ignored fake_bus"]
        async fn fake_bus_the_lookups_and_the_hint_through_a_real_bus() {
            let dir = tempfile::tempdir().unwrap();
            let listen = format!("unix:path={}", dir.path().join("bus").display());
            let mut daemon = Command::new("dbus-daemon")
                .args(["--session", "--nofork", "--print-address=1"])
                .arg(format!("--address={listen}"))
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .expect("dbus-daemon runs (this test needs it on the PATH)");
            let mut line = String::new();
            BufReader::new(daemon.stdout.take().unwrap())
                .read_line(&mut line)
                .unwrap();
            let address = line.trim().to_owned();
            let own_locked = Arc::new(AtomicBool::new(false));
            let desk_locked = Arc::new(AtomicBool::new(false));
            let _logind = zbus::connection::Builder::address(address.as_str())
                .unwrap()
                .name(LOGIN)
                .unwrap()
                .serve_at(MANAGER_PATH, Manager)
                .unwrap()
                .serve_at(
                    OWN,
                    Session {
                        id: "32",
                        kind: "tty",
                        locked: Arc::clone(&own_locked),
                    },
                )
                .unwrap()
                .serve_at(
                    DESK,
                    Session {
                        id: "31",
                        kind: "wayland",
                        locked: Arc::clone(&desk_locked),
                    },
                )
                .unwrap()
                .serve_at(USER_PATH, User)
                .unwrap()
                .build()
                .await
                .unwrap();
            let conn = zbus::connection::Builder::address(address.as_str())
                .unwrap()
                .build()
                .await
                .unwrap();
            let uid = || Ok(1000);

            // polkit: the process's own session whatever its type, else the
            // display session.
            assert_eq!(
                session_id(&conn, IN_SESSION, uid).await,
                Ok("32".to_owned())
            );
            assert_eq!(session_id(&conn, 7, uid).await, Ok("31".to_owned()));
            // The lock: a `tty` session gives way to the display session.
            let desk = desktop_session(&conn, IN_SESSION, uid).await.unwrap();
            assert_eq!(desk.as_str(), DESK);
            assert_eq!(desktop_session(&conn, 7, uid).await.unwrap().as_str(), DESK);
            assert!(desktop_session(&conn, 7, || Ok(5)).await.is_err());
            // The hint as the desktop's locker sets it, and only that
            // session's.
            let hint = || crate::lock::read_hint(&conn, desk.as_str());
            assert_eq!(hint().await, Some(false));
            desk_locked.store(true, Ordering::SeqCst);
            assert_eq!(hint().await, Some(true));
            own_locked.store(false, Ordering::SeqCst);
            desk_locked.store(false, Ordering::SeqCst);
            assert_eq!(hint().await, Some(false));
            // An object that is not there is an error, not a reading.
            assert!(
                conn.property("/org/freedesktop/login1/session/_9", SESSION, "LockedHint")
                    .await
                    .is_err()
            );
            drop(conn);
            let _ = daemon.kill();
            let _ = daemon.wait();
        }
    }
}
