//! Linux: a desktop notification with one action, over the session D-Bus
//! (`org.freedesktop.Notifications`, the Desktop Notifications
//! Specification). It is the block window's best effort where no client window
//! can stay above the others (Wayland; `docs/PLAN.md` §B.8.6.3): the
//! notification carries the window's one control, Block, as an action, and the
//! chime as its `sound-name` hint. It is sent over the `zbus` this crate
//! already uses (the plan names `notify-rust`, which drives the same
//! interface; no new crate). What a notification server does with it (shows
//! the button, plays the sound, keeps the notification up while the window
//! runs) is the server's: NEEDS-DEVICE(gnome). The same bus carries the
//! notification that mirrors a request's sheet in background mode
//! ([`mirror_notice`], §B.1.1), which has no action.
//!
//! The bus is a seam ([`NotificationBus`]), so the request can be checked on a
//! fake one; [`SessionBus`] is the user's session bus.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::mpsc;

use crate::polkit::BoxFuture;

/// The notification service's well-known name, which is also its interface.
const NOTIFICATIONS: &str = "org.freedesktop.Notifications";
/// The notification service's object.
const NOTIFICATIONS_PATH: &str = "/org/freedesktop/Notifications";
/// The application name the notifications are sent with.
const APP_NAME: &str = "Tornect";

/// The action key of Block.
pub const BLOCK_ACTION: &str = "block";
/// The chime: the freedesktop sound theme's name for a warning.
pub const CHIME: &str = "dialog-warning";
/// The `urgency` hint of a notification that must not go unseen (critical).
pub const URGENCY_CRITICAL: u8 = 2;
/// The `urgency` hint of an ordinary notification (normal).
pub const URGENCY_NORMAL: u8 = 1;

/// Why a notification could not be shown.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct NotifyError(String);

/// One notification as `Notify` sends it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    /// The summary line.
    pub summary: String,
    /// The body.
    pub body: String,
    /// Its actions, `(key, label)`, in order.
    pub actions: Vec<(String, String)>,
    /// The `sound-name` hint.
    pub sound: Option<String>,
    /// The `urgency` hint (0 low, 1 normal, 2 critical).
    pub urgency: u8,
    /// How long the server may keep it up, in ms (`expire_timeout`).
    pub expire_ms: i32,
}

impl Notice {
    /// The `actions` argument of `Notify`: keys and labels alternating.
    #[must_use]
    pub fn action_list(&self) -> Vec<&str> {
        self.actions
            .iter()
            .flat_map(|(key, label)| [key.as_str(), label.as_str()])
            .collect()
    }

    /// The `hints` argument of `Notify`.
    #[must_use]
    pub fn hints(&self) -> HashMap<&'static str, zbus::zvariant::Value<'_>> {
        let mut hints = HashMap::new();
        hints.insert("urgency", zbus::zvariant::Value::U8(self.urgency));
        if let Some(sound) = &self.sound {
            hints.insert("sound-name", zbus::zvariant::Value::from(sound.as_str()));
        }
        hints
    }
}

/// The block window's notification for `label`'s request, which starts in
/// `secs` seconds: critical, with Block and the chime, up for the window's
/// length.
#[must_use]
pub fn block_notice(label: &str, secs: u8) -> Notice {
    Notice {
        summary: format!("\"{label}\" is connecting without asking"),
        body: format!("The session starts in {secs} s unless you block it."),
        actions: vec![(BLOCK_ACTION.to_owned(), "Block".to_owned())],
        sound: Some(CHIME.to_owned()),
        urgency: URGENCY_CRITICAL,
        expire_ms: i32::from(secs) * 1000,
    }
}

/// A notification that mirrors a question on screen (`docs/PLAN.md` §B.1.1:
/// in background mode each request's sheet has one): normal, with no action
/// and no sound, and no time limit of its own (`expire_timeout` 0), because
/// it is taken down with its question.
#[must_use]
pub fn mirror_notice(summary: &str, body: &str) -> Notice {
    Notice {
        summary: summary.to_owned(),
        body: body.to_owned(),
        actions: Vec::new(),
        sound: None,
        urgency: URGENCY_NORMAL,
        expire_ms: 0,
    }
}

/// What a notice needs of the session bus.
pub trait NotificationBus: Send + Sync {
    /// Start listening for invoked actions, as `(notification id, action key)`;
    /// called before [`Self::notify`], so no answer can come before the
    /// listener.
    fn actions(&self) -> BoxFuture<'_, Result<mpsc::Receiver<(u32, String)>, NotifyError>>;
    /// Show `notice`; its id.
    fn notify<'a>(&'a self, notice: &'a Notice) -> BoxFuture<'a, Result<u32, NotifyError>>;
    /// Take notification `id` down.
    fn close(&self, id: u32) -> BoxFuture<'_, ()>;
}

/// A notice on screen; dropping it takes the notification down.
pub struct Shown {
    bus: Arc<dyn NotificationBus>,
    id: u32,
    actions: mpsc::Receiver<(u32, String)>,
}

impl std::fmt::Debug for Shown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shown")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl Shown {
    /// Show `notice` on `bus`.
    pub async fn show(bus: Arc<dyn NotificationBus>, notice: &Notice) -> Result<Self, NotifyError> {
        let actions = bus.actions().await?;
        let id = bus.notify(notice).await?;
        Ok(Self { bus, id, actions })
    }

    /// The next action invoked on this notice; `None` once none can come.
    pub async fn action(&mut self) -> Option<String> {
        while let Some((id, key)) = self.actions.recv().await {
            if id == self.id {
                return Some(key);
            }
        }
        None
    }
}

impl Drop for Shown {
    fn drop(&mut self) {
        // Taken down off the caller's path: a window that ended does not wait
        // on the bus.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let (bus, id) = (Arc::clone(&self.bus), self.id);
            runtime.spawn(async move { bus.close(id).await });
        }
    }
}

/// The user's session bus.
#[derive(Debug, Clone)]
pub struct SessionBus {
    conn: zbus::Connection,
}

impl SessionBus {
    /// Connect to the session bus.
    pub async fn connect() -> Result<Self, NotifyError> {
        let conn = zbus::Connection::session()
            .await
            .map_err(|e| NotifyError(format!("session D-Bus unavailable: {e}")))?;
        Ok(Self { conn })
    }
}

impl NotificationBus for SessionBus {
    fn actions(&self) -> BoxFuture<'_, Result<mpsc::Receiver<(u32, String)>, NotifyError>> {
        Box::pin(async move {
            // The bus delivers only the service's own signals (a well-known
            // sender is matched by the bus, against its current owner).
            let rule = zbus::MatchRule::builder()
                .msg_type(zbus::message::Type::Signal)
                .sender(NOTIFICATIONS)
                .and_then(|b| b.path(NOTIFICATIONS_PATH))
                .and_then(|b| b.interface(NOTIFICATIONS))
                .and_then(|b| b.member("ActionInvoked"))
                .map_err(|e| NotifyError(format!("match rule: {e}")))?
                .build();
            let stream = zbus::MessageStream::for_match_rule(rule, &self.conn, Some(8))
                .await
                .map_err(|e| NotifyError(format!("subscribing to ActionInvoked: {e}")))?;
            let (tx, rx) = mpsc::channel(4);
            tokio::spawn(forward_actions(stream, tx));
            Ok(rx)
        })
    }

    fn notify<'a>(&'a self, notice: &'a Notice) -> BoxFuture<'a, Result<u32, NotifyError>> {
        Box::pin(async move {
            let reply = self
                .conn
                .call_method(
                    Some(NOTIFICATIONS),
                    NOTIFICATIONS_PATH,
                    Some(NOTIFICATIONS),
                    "Notify",
                    &(
                        APP_NAME,
                        0u32,
                        "",
                        notice.summary.as_str(),
                        notice.body.as_str(),
                        notice.action_list(),
                        notice.hints(),
                        notice.expire_ms,
                    ),
                )
                .await
                .map_err(|e| NotifyError(format!("Notify: {e}")))?;
            reply
                .body()
                .deserialize::<u32>()
                .map_err(|e| NotifyError(format!("Notify: {e}")))
        })
    }

    fn close(&self, id: u32) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            if let Err(e) = self
                .conn
                .call_method(
                    Some(NOTIFICATIONS),
                    NOTIFICATIONS_PATH,
                    Some(NOTIFICATIONS),
                    "CloseNotification",
                    &(id,),
                )
                .await
            {
                tracing::debug!(error = %e, "CloseNotification");
            }
        })
    }
}

/// Forward each `ActionInvoked` of `stream` to `tx` until the stream ends or
/// fails, or the receiver is dropped.
async fn forward_actions<S>(mut stream: S, tx: mpsc::Sender<(u32, String)>)
where
    S: zbus::export::futures_core::Stream<Item = zbus::Result<zbus::Message>> + Unpin,
{
    loop {
        tokio::select! {
            () = tx.closed() => break,
            next = std::future::poll_fn(|cx| std::pin::Pin::new(&mut stream).poll_next(cx)) => match next {
                Some(Ok(message)) => {
                    if let Ok(invoked) = message.body().deserialize::<(u32, String)>()
                        && tx.send(invoked).await.is_err()
                    {
                        break;
                    }
                }
                Some(Err(_)) | None => break,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// A bus that records what it is asked and lets the test invoke actions.
    #[derive(Default)]
    struct FakeBus {
        shown: Mutex<Vec<Notice>>,
        closed: Mutex<Vec<u32>>,
        invoke: Mutex<Option<mpsc::Sender<(u32, String)>>>,
    }

    impl NotificationBus for FakeBus {
        fn actions(&self) -> BoxFuture<'_, Result<mpsc::Receiver<(u32, String)>, NotifyError>> {
            let (tx, rx) = mpsc::channel(4);
            *self.invoke.lock().unwrap() = Some(tx);
            Box::pin(async move { Ok(rx) })
        }

        fn notify<'a>(&'a self, notice: &'a Notice) -> BoxFuture<'a, Result<u32, NotifyError>> {
            assert!(
                self.invoke.lock().unwrap().is_some(),
                "listening before the notification is shown"
            );
            self.shown.lock().unwrap().push(notice.clone());
            Box::pin(async { Ok(7) })
        }

        fn close(&self, id: u32) -> BoxFuture<'_, ()> {
            self.closed.lock().unwrap().push(id);
            Box::pin(async {})
        }
    }

    /// The block window's notification on a fake bus: critical, with Block as
    /// its one action and the chime as its sound, up for the window's length;
    /// Block on another notification is not this one's; dropped, it is taken
    /// down.
    #[tokio::test]
    async fn the_block_notice_on_a_fake_bus() {
        let bus = Arc::new(FakeBus::default());
        let mut shown = Shown::show(bus.clone(), &block_notice("Laptop", 10))
            .await
            .unwrap();
        let notice = bus.shown.lock().unwrap()[0].clone();
        assert_eq!(
            notice,
            Notice {
                summary: "\"Laptop\" is connecting without asking".to_owned(),
                body: "The session starts in 10 s unless you block it.".to_owned(),
                actions: vec![("block".to_owned(), "Block".to_owned())],
                sound: Some("dialog-warning".to_owned()),
                urgency: 2,
                expire_ms: 10_000,
            }
        );
        assert_eq!(notice.action_list(), vec!["block", "Block"]);
        let hints = notice.hints();
        assert_eq!(hints.len(), 2);
        assert_eq!(hints["urgency"], zbus::zvariant::Value::U8(2));
        assert_eq!(
            hints["sound-name"],
            zbus::zvariant::Value::from("dialog-warning")
        );

        let invoke = bus.invoke.lock().unwrap().clone().unwrap();
        invoke.send((8, "block".to_owned())).await.unwrap();
        invoke.send((7, "block".to_owned())).await.unwrap();
        assert_eq!(shown.action().await.as_deref(), Some(BLOCK_ACTION));

        drop(shown);
        for _ in 0..100 {
            if !bus.closed.lock().unwrap().is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(*bus.closed.lock().unwrap(), vec![7]);
    }

    /// A notification that mirrors a question on a fake bus: normal, with no
    /// action and no sound, never expiring by itself; dropped, it is taken
    /// down.
    #[tokio::test]
    async fn a_mirror_notice_on_a_fake_bus() {
        let bus = Arc::new(FakeBus::default());
        let shown = Shown::show(bus.clone(), &mirror_notice("A summary.", "A body."))
            .await
            .unwrap();
        let notice = bus.shown.lock().unwrap()[0].clone();
        assert_eq!(
            notice,
            Notice {
                summary: "A summary.".to_owned(),
                body: "A body.".to_owned(),
                actions: Vec::new(),
                sound: None,
                urgency: 1,
                expire_ms: 0,
            }
        );
        assert!(notice.action_list().is_empty());
        let hints = notice.hints();
        assert_eq!(hints.len(), 1);
        assert_eq!(hints["urgency"], zbus::zvariant::Value::U8(1));
        drop(shown);
        for _ in 0..100 {
            if !bus.closed.lock().unwrap().is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(*bus.closed.lock().unwrap(), vec![7]);
    }
}
