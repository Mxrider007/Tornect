//! Revoking polkit's remembered approvals during a Control session
//! (`docs/PLAN.md` §B.2.1, M-FEAT-2).
//!
//! On Linux "without administrator access" cannot be enforced beyond the
//! system's own password dialogs: an approval polkit remembers for this
//! session (an `auth_admin_keep` action answered a moment ago) would let the
//! remote run the same kind of action again without the password. So when
//! every Control session starts, and whenever the authority reports a
//! change while it lasts, this session's remembered approvals are revoked —
//! `pkcheck --revoke-temp`'s semantics, "revoke all temporary authorizations
//! for the current session" (pkcheck(1)). It only makes the person at the
//! computer type a password again; it is not enforcement, and a `sudo`
//! credential cached in an open terminal is out of its reach.
//!
//! The D-Bus methods, read from polkitd 127's introspection on the build VM
//! (`busctl introspect org.freedesktop.PolicyKit1
//! /org/freedesktop/PolicyKit1/Authority`, 2026-09-28):
//! `RevokeTemporaryAuthorizations((sa{sv}) subject)`,
//! `EnumerateTemporaryAuthorizations((sa{sv}) subject) → a(ss(sa{sv})tt)`,
//! and the signal `Changed()`. The subject is the `unix-session` of this
//! process: logind's session of this process, or else the user's display
//! session (what `pkcheck --revoke-temp` resolves when it runs outside a
//! session: it answered 0 from an SSH-less terminal of the build VM that
//! belongs to no session). A change is answered by revoking only while
//! remembered approvals exist, so a revocation's own `Changed` never loops.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// A boxed future, as the other seams of this crate take them.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Why the authority could not be asked.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("polkit: {0}")]
pub struct PolkitError(pub String);

/// polkit's authority, as far as the revocation needs it: the real one over
/// the system D-Bus ([`SystemAuthority`], Linux), or a fake in tests.
pub trait TemporaryAuthority: Send + Sync {
    /// Revoke every remembered approval of this session.
    fn revoke(&self) -> BoxFuture<'_, Result<(), PolkitError>>;

    /// How many remembered approvals this session holds.
    fn remembered(&self) -> BoxFuture<'_, Result<usize, PolkitError>>;

    /// A channel that receives one `()` per `Changed` signal of the
    /// authority, from the moment this returns.
    fn changes(&self) -> BoxFuture<'_, Result<tokio::sync::mpsc::Receiver<()>, PolkitError>>;
}

/// While alive, keeps this session free of remembered polkit approvals: it
/// revoked them when the Control session started and revokes them again
/// whenever the authority reports a change. Dropped when the session ends.
#[derive(Debug)]
pub struct RevokeGuard {
    task: tokio::task::JoinHandle<()>,
}

impl RevokeGuard {
    /// Whether the watch has stopped (the authority went away).
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }

    /// Resolves when the watch stops before the session ends: the
    /// authority's signals stopped (the bus connection or polkit went
    /// away), so a later change is no longer answered.
    pub async fn stopped(&mut self) {
        let _ = (&mut self.task).await;
    }
}

impl Drop for RevokeGuard {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// What the first revocation did, for the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Started {
    /// Revoked, and watching for changes.
    Revoked,
    /// Revoked once, but the authority's changes could not be subscribed
    /// to: nothing is revoked again during the session.
    Unwatched(PolkitError),
    /// The authority could not be asked; nothing is watched.
    Failed(PolkitError),
}

/// Start guarding a Control session: subscribe to the authority's changes
/// first (so none is missed), revoke once, then revoke again after every
/// change that left remembered approvals. Needs a tokio runtime.
pub async fn guard_control_session(
    authority: Arc<dyn TemporaryAuthority>,
) -> (Option<RevokeGuard>, Started) {
    let mut changes = match authority.changes().await {
        Ok(rx) => rx,
        // The revocation needs no subscription: revoke once all the same.
        Err(e) => {
            return match authority.revoke().await {
                Ok(()) => (None, Started::Unwatched(e)),
                Err(revoke) => (None, Started::Failed(revoke)),
            };
        }
    };
    if let Err(e) = authority.revoke().await {
        return (None, Started::Failed(e));
    }
    let task = tokio::spawn(async move {
        while changes.recv().await.is_some() {
            // Coalesce a burst: one look per wake-up.
            while changes.try_recv().is_ok() {}
            match authority.remembered().await {
                Ok(0) => {}
                Ok(n) => {
                    if let Err(e) = authority.revoke().await {
                        tracing::warn!(error = %e, remembered = n, "revoking polkit's remembered approvals");
                    } else {
                        tracing::info!(
                            remembered = n,
                            "revoked polkit's remembered approvals during a Control session"
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "reading polkit's remembered approvals");
                }
            }
        }
    });
    (Some(RevokeGuard { task }), Started::Revoked)
}

/// polkit's authority on the system D-Bus, for this process's session.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
pub struct SystemAuthority {
    conn: zbus::Connection,
    session_id: String,
}

#[cfg(target_os = "linux")]
const POLKIT: &str = "org.freedesktop.PolicyKit1";
#[cfg(target_os = "linux")]
const AUTHORITY_PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
#[cfg(target_os = "linux")]
const AUTHORITY: &str = "org.freedesktop.PolicyKit1.Authority";

#[cfg(target_os = "linux")]
impl SystemAuthority {
    /// Connect to the system bus and find this process's session: logind's
    /// session of this process, or else the user's display session.
    pub async fn connect() -> Result<Self, PolkitError> {
        let conn = zbus::Connection::system()
            .await
            .map_err(|e| PolkitError(format!("system D-Bus unavailable: {e}")))?;
        let session_id = session_id(&conn).await?;
        Ok(Self { conn, session_id })
    }

    /// The logind session id the subject names.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    fn subject(&self) -> Subject<'_> {
        let mut details = std::collections::HashMap::new();
        details.insert(
            "session-id",
            zbus::zvariant::Value::from(self.session_id.as_str()),
        );
        Subject {
            kind: "unix-session",
            details,
        }
    }
}

/// `(sa{sv})` — a polkit subject.
#[cfg(target_os = "linux")]
#[derive(Debug, serde::Serialize, zbus::zvariant::Type)]
struct Subject<'a> {
    kind: &'a str,
    details: std::collections::HashMap<&'a str, zbus::zvariant::Value<'a>>,
}

/// `org.freedesktop.DBus.Properties.Get` of logind object `path`.
#[cfg(target_os = "linux")]
async fn logind_property(
    conn: &zbus::Connection,
    path: &str,
    iface: &str,
    name: &str,
) -> Result<zbus::zvariant::OwnedValue, PolkitError> {
    let reply = conn
        .call_method(
            Some("org.freedesktop.login1"),
            path,
            Some("org.freedesktop.DBus.Properties"),
            "Get",
            &(iface, name),
        )
        .await
        .map_err(|e| PolkitError(format!("logind {iface}.{name}: {e}")))?;
    reply
        .body()
        .deserialize::<zbus::zvariant::OwnedValue>()
        .map_err(|e| PolkitError(format!("logind {iface}.{name}: {e}")))
}

/// The string inside a property value (a variant of `s`, or a structure
/// whose first field is one, as `User.Display`'s `(so)`).
#[cfg(target_os = "linux")]
fn first_str(value: &zbus::zvariant::Value<'_>) -> Option<String> {
    use zbus::zvariant::Value;
    match value {
        Value::Str(s) => Some(s.to_string()),
        Value::Value(inner) => first_str(inner),
        Value::Structure(st) => st.fields().first().and_then(first_str),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
async fn session_id(conn: &zbus::Connection) -> Result<String, PolkitError> {
    const LOGIN: &str = "org.freedesktop.login1";
    const MANAGER_PATH: &str = "/org/freedesktop/login1";
    const MANAGER: &str = "org.freedesktop.login1.Manager";
    let by_pid = conn
        .call_method(
            Some(LOGIN),
            MANAGER_PATH,
            Some(MANAGER),
            "GetSessionByPID",
            &(std::process::id(),),
        )
        .await;
    if let Ok(reply) = by_pid
        && let Ok(path) = reply
            .body()
            .deserialize::<zbus::zvariant::OwnedObjectPath>()
    {
        let id =
            logind_property(conn, path.as_str(), "org.freedesktop.login1.Session", "Id").await?;
        return first_str(&id)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| PolkitError("logind gave no session id".to_owned()));
    }
    // Outside a session (a user service, a terminal of no session): the
    // user's display session, as polkit itself falls back to.
    let uid = {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::metadata("/proc/self")
            .map_err(|e| PolkitError(format!("reading this process's uid: {e}")))?
            .uid()
    };
    let user = conn
        .call_method(Some(LOGIN), MANAGER_PATH, Some(MANAGER), "GetUser", &(uid,))
        .await
        .map_err(|e| PolkitError(format!("logind GetUser: {e}")))?
        .body()
        .deserialize::<zbus::zvariant::OwnedObjectPath>()
        .map_err(|e| PolkitError(format!("logind GetUser: {e}")))?;
    let display = logind_property(
        conn,
        user.as_str(),
        "org.freedesktop.login1.User",
        "Display",
    )
    .await?;
    first_str(&display)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| PolkitError("this user has no session to revoke approvals in".to_owned()))
}

#[cfg(target_os = "linux")]
impl TemporaryAuthority for SystemAuthority {
    fn revoke(&self) -> BoxFuture<'_, Result<(), PolkitError>> {
        Box::pin(async move {
            self.conn
                .call_method(
                    Some(POLKIT),
                    AUTHORITY_PATH,
                    Some(AUTHORITY),
                    "RevokeTemporaryAuthorizations",
                    &(self.subject(),),
                )
                .await
                .map(drop)
                .map_err(|e| PolkitError(format!("RevokeTemporaryAuthorizations: {e}")))
        })
    }

    fn remembered(&self) -> BoxFuture<'_, Result<usize, PolkitError>> {
        Box::pin(async move {
            /// `(ss(sa{sv})tt)` — one temporary authorization.
            #[derive(Debug, serde::Deserialize, zbus::zvariant::Type)]
            #[allow(dead_code)] // only counted
            struct Temporary {
                id: String,
                action_id: String,
                subject: (
                    String,
                    std::collections::HashMap<String, zbus::zvariant::OwnedValue>,
                ),
                obtained: u64,
                expires: u64,
            }
            let reply = self
                .conn
                .call_method(
                    Some(POLKIT),
                    AUTHORITY_PATH,
                    Some(AUTHORITY),
                    "EnumerateTemporaryAuthorizations",
                    &(self.subject(),),
                )
                .await
                .map_err(|e| PolkitError(format!("EnumerateTemporaryAuthorizations: {e}")))?;
            let list: Vec<Temporary> = reply
                .body()
                .deserialize()
                .map_err(|e| PolkitError(format!("EnumerateTemporaryAuthorizations: {e}")))?;
            Ok(list.len())
        })
    }

    fn changes(&self) -> BoxFuture<'_, Result<tokio::sync::mpsc::Receiver<()>, PolkitError>> {
        Box::pin(async move {
            let rule = zbus::MatchRule::builder()
                .msg_type(zbus::message::Type::Signal)
                .sender(POLKIT)
                .and_then(|b| b.path(AUTHORITY_PATH))
                .and_then(|b| b.interface(AUTHORITY))
                .and_then(|b| b.member("Changed"))
                .map_err(|e| PolkitError(format!("match rule: {e}")))?
                .build();
            let stream = zbus::MessageStream::for_match_rule(rule, &self.conn, Some(16))
                .await
                .map_err(|e| PolkitError(format!("subscribing to Changed: {e}")))?;
            let (tx, rx) = tokio::sync::mpsc::channel(4);
            tokio::spawn(forward_changes(stream, tx));
            Ok(rx)
        })
    }
}

/// Forward one `()` per item of `stream` to `tx` until the stream ends or
/// fails, or the receiver is dropped, whichever comes first. The receiver's
/// end is watched beside the stream, so the task ends — and drops the
/// stream, its match rule and its hold on the bus connection — the moment
/// the Control session's watch goes, not at the authority's next `Changed`,
/// which on a quiet desktop can be days away.
#[cfg(target_os = "linux")]
async fn forward_changes<S, T, E>(mut stream: S, tx: tokio::sync::mpsc::Sender<()>)
where
    S: zbus::export::futures_core::Stream<Item = Result<T, E>> + Unpin,
{
    loop {
        tokio::select! {
            () = tx.closed() => break,
            next = std::future::poll_fn(|cx| Pin::new(&mut stream).poll_next(cx)) => match next {
                // A full channel already holds a wake-up.
                Some(Ok(_)) => drop(tx.try_send(())),
                Some(Err(_)) | None => break,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use tokio::sync::mpsc;

    use super::*;

    /// A fake authority: remembered approvals, a revoke that clears them and
    /// — like polkitd — reports a change when it removed something.
    #[derive(Default)]
    struct Fake {
        remembered: AtomicUsize,
        revokes: AtomicUsize,
        fail: bool,
        tx: Mutex<Option<mpsc::Sender<()>>>,
    }

    impl Fake {
        fn change(&self) {
            if let Some(tx) = self.tx.lock().unwrap().as_ref() {
                let _ = tx.try_send(());
            }
        }

        /// Something outside answered an `auth_admin_keep` dialog.
        fn remember(&self) {
            self.remembered.fetch_add(1, Ordering::SeqCst);
            self.change();
        }
    }

    impl TemporaryAuthority for Fake {
        fn revoke(&self) -> BoxFuture<'_, Result<(), PolkitError>> {
            Box::pin(async move {
                if self.fail {
                    return Err(PolkitError("no authority".to_owned()));
                }
                self.revokes.fetch_add(1, Ordering::SeqCst);
                if self.remembered.swap(0, Ordering::SeqCst) > 0 {
                    self.change();
                }
                Ok(())
            })
        }

        fn remembered(&self) -> BoxFuture<'_, Result<usize, PolkitError>> {
            Box::pin(async move { Ok(self.remembered.load(Ordering::SeqCst)) })
        }

        fn changes(&self) -> BoxFuture<'_, Result<mpsc::Receiver<()>, PolkitError>> {
            Box::pin(async move {
                let (tx, rx) = mpsc::channel(4);
                *self.tx.lock().unwrap() = Some(tx);
                Ok(rx)
            })
        }
    }

    async fn settle() {
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    /// The Control session's start revokes; a change that left remembered
    /// approvals revokes again; the revocation's own change does not loop;
    /// the session's end stops the watch.
    #[tokio::test]
    async fn revoked_at_the_start_and_after_every_change() {
        let fake = Arc::new(Fake::default());
        fake.remembered.store(2, Ordering::SeqCst);
        let (guard, started) = guard_control_session(fake.clone()).await;
        assert_eq!(started, Started::Revoked);
        let guard = guard.expect("watching");
        settle().await;
        assert_eq!(fake.remembered.load(Ordering::SeqCst), 0);
        assert_eq!(
            fake.revokes.load(Ordering::SeqCst),
            1,
            "its own change looped"
        );
        fake.remember();
        settle().await;
        assert_eq!(
            fake.remembered.load(Ordering::SeqCst),
            0,
            "a change left an approval"
        );
        assert_eq!(fake.revokes.load(Ordering::SeqCst), 2);
        // A change with nothing remembered (another session's, a reload).
        fake.change();
        settle().await;
        assert_eq!(fake.revokes.load(Ordering::SeqCst), 2);
        drop(guard);
        settle().await;
        fake.remember();
        settle().await;
        assert_eq!(
            fake.remembered.load(Ordering::SeqCst),
            1,
            "watched after the session ended"
        );
    }

    /// An authority whose changes cannot be subscribed to is still revoked
    /// once, and says that nothing is watched; a watch whose signals stop
    /// ends, and says so.
    #[tokio::test]
    async fn without_a_subscription_the_start_still_revokes() {
        struct Deaf(AtomicUsize);
        impl TemporaryAuthority for Deaf {
            fn revoke(&self) -> BoxFuture<'_, Result<(), PolkitError>> {
                Box::pin(async move {
                    self.0.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })
            }
            fn remembered(&self) -> BoxFuture<'_, Result<usize, PolkitError>> {
                Box::pin(async { Ok(0) })
            }
            fn changes(&self) -> BoxFuture<'_, Result<mpsc::Receiver<()>, PolkitError>> {
                Box::pin(async { Err(PolkitError("no match rule".to_owned())) })
            }
        }
        let deaf = Arc::new(Deaf(AtomicUsize::new(0)));
        let (guard, started) = guard_control_session(deaf.clone()).await;
        assert!(guard.is_none());
        assert_eq!(
            started,
            Started::Unwatched(PolkitError("no match rule".to_owned()))
        );
        assert_eq!(deaf.0.load(Ordering::SeqCst), 1, "revoked once");

        let fake = Arc::new(Fake::default());
        let (guard, started) = guard_control_session(fake.clone()).await;
        assert_eq!(started, Started::Revoked);
        let mut guard = guard.expect("watching");
        // The signals stop: the watch ends, and says so.
        drop(fake.tx.lock().unwrap().take());
        tokio::time::timeout(Duration::from_secs(5), guard.stopped())
            .await
            .expect("the watch said it stopped");
    }

    /// A stream of the authority's signals that never yields: the quiet
    /// desktop. It says when it is dropped.
    #[cfg(target_os = "linux")]
    struct Quiet(Arc<std::sync::atomic::AtomicBool>);

    #[cfg(target_os = "linux")]
    impl zbus::export::futures_core::Stream for Quiet {
        type Item = Result<(), PolkitError>;

        fn poll_next(
            self: Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            std::task::Poll::Pending
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for Quiet {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// When the Control session's watch ends, the task that forwards the
    /// authority's signals ends too, and drops its subscription (the match
    /// rule and the connection it holds), though no signal came.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn an_ended_watch_leaves_no_subscription_behind() {
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (tx, rx) = mpsc::channel(4);
        let task = tokio::spawn(forward_changes(Quiet(Arc::clone(&dropped)), tx));
        settle().await;
        assert!(!task.is_finished(), "it forwards while the watch lives");
        drop(rx);
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("the forwarder ended with the watch")
            .expect("it did not panic");
        assert!(
            dropped.load(Ordering::SeqCst),
            "its subscription was dropped"
        );
    }

    /// An authority that cannot be asked is reported, not hidden.
    #[tokio::test]
    async fn a_failed_revocation_is_reported() {
        let fake = Arc::new(Fake {
            fail: true,
            ..Fake::default()
        });
        let (guard, started) = guard_control_session(fake).await;
        assert!(guard.is_none());
        assert_eq!(
            started,
            Started::Failed(PolkitError("no authority".to_owned()))
        );
    }
    /// The real authority of this machine: find this process's session,
    /// revoke its remembered approvals (no dialog), and see none left.
    /// Talks to the system D-Bus, so it is run by hand:
    /// `cargo test --workspace -- --ignored live_polkit_revocation`.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "talks to this machine's polkit over the system D-Bus"]
    async fn live_polkit_revocation() {
        let authority = SystemAuthority::connect()
            .await
            .expect("the system bus and a session");
        assert!(!authority.session_id().is_empty());
        let before = authority
            .remembered()
            .await
            .expect("EnumerateTemporaryAuthorizations");
        let changes = authority.changes().await.expect("subscribing to Changed");
        authority
            .revoke()
            .await
            .expect("RevokeTemporaryAuthorizations");
        let after = authority
            .remembered()
            .await
            .expect("EnumerateTemporaryAuthorizations");
        assert_eq!(after, 0, "{before} remembered before the revocation");
        drop(changes);
    }
}
