//! The desktop notification that mirrors a host sheet while Tornect runs in
//! background mode (`docs/PLAN.md` §B.1.1): the sheet raises the window as
//! every sheet does, and the notification says that a device asks, in a fixed
//! text that names no device and carries no device words (§B.6.1 W-B4). It is
//! never the only sign (§B.8.7.3: never a notification alone), and it goes
//! when its sheet goes, however the sheet ends. A pairing from a new device
//! is asked exactly as with the window open (decision M1-68): the
//! notification only reads which sheets are open, and answers nothing.
//!
//! On Linux it goes to the session bus (`tornect_platform::notify`); on
//! Windows it is a notification-area balloon (`tornect_platform::win_notify`),
//! which Windows 10 and 11 show as a toast; this build shows none on other
//! systems.

use std::sync::Arc;

use tokio::sync::mpsc;

use super::model::{Popup, PopupKind, Shared};

/// Where a notification sends the person: the sheet in the window.
#[cfg_attr(not(any(target_os = "linux", windows)), allow(dead_code))]
const ANSWER: &str = "Open Tornect to answer.";

/// What a sheet asks, as its notification says it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asks {
    /// A device asks to pair.
    Pair,
    /// A device asks for a session, "Ask before starting" included.
    Connect,
}

impl Asks {
    /// What `kind` asks.
    #[must_use]
    pub fn of(kind: &PopupKind) -> Self {
        match kind {
            PopupKind::Pairing { .. } => Self::Pair,
            PopupKind::Session { .. } | PopupKind::Ask { .. } => Self::Connect,
        }
    }

    /// The notification's two lines: what is asked, and where to answer.
    #[must_use]
    #[cfg_attr(not(any(target_os = "linux", windows)), allow(dead_code))]
    pub fn lines(self) -> (&'static str, &'static str) {
        match self {
            Self::Pair => ("A device asks to pair with this computer.", ANSWER),
            Self::Connect => ("A device asks to connect to this computer.", ANSWER),
        }
    }
}

/// A change the notifications need, for the sheets open now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoticeChange {
    /// Sheet `sheet` opened: show its notification.
    Show {
        /// The sheet's id.
        sheet: u64,
        /// What it asks.
        asks: Asks,
    },
    /// Sheet `sheet` closed: take its notification down.
    Close {
        /// The sheet's id.
        sheet: u64,
    },
}

/// Which sheets have their notification: one per open host sheet.
#[derive(Debug, Default)]
pub struct Notices {
    shown: Vec<u64>,
}

impl Notices {
    /// Take in the sheets open now; the changes that make the notifications
    /// match them, the closes first.
    pub fn sync(&mut self, popups: &[Popup]) -> Vec<NoticeChange> {
        let mut changes = Vec::new();
        self.shown.retain(|sheet| {
            let open = popups.iter().any(|p| p.id == *sheet);
            if !open {
                changes.push(NoticeChange::Close { sheet: *sheet });
            }
            open
        });
        for popup in popups {
            if !self.shown.contains(&popup.id) {
                self.shown.push(popup.id);
                changes.push(NoticeChange::Show {
                    sheet: popup.id,
                    asks: Asks::of(&popup.kind),
                });
            }
        }
        changes
    }
}

/// Start mirroring for the window whose model is `shared`: the returned
/// sender takes the window's changes. On Linux they reach the session bus, on
/// Windows the notification area; elsewhere they are dropped.
pub fn start(shared: Arc<Shared>) -> mpsc::UnboundedSender<NoticeChange> {
    let (tx, rx) = mpsc::unbounded_channel();
    let note = move |line: String| shared.update(|m| m.note(line));
    #[cfg(target_os = "linux")]
    tokio::spawn(mirror(
        || async {
            tornect_platform::notify::SessionBus::connect()
                .await
                .map(|bus| Arc::new(bus) as Arc<dyn tornect_platform::notify::NotificationBus>)
        },
        rx,
        note,
    ));
    #[cfg(windows)]
    tokio::spawn(mirror_windows(rx, note));
    #[cfg(not(any(target_os = "linux", windows)))]
    drop((rx, note));
    tx
}

/// The id of `sheet`'s notification-area icon (sheet ids count up from 1 in
/// a process).
#[cfg(windows)]
fn icon_id(sheet: u64) -> u32 {
    u32::try_from(sheet).unwrap_or(u32::MAX)
}

/// Show and take down the Windows notifications as `changes` say, until
/// `changes` ends: the notifications' thread starts at the first one, and
/// one that cannot start is said once through `note`; the sheets raise the
/// window all the same. Never called in a test: only the window's backend
/// starts it, in background mode.
#[cfg(windows)]
async fn mirror_windows(mut changes: mpsc::UnboundedReceiver<NoticeChange>, note: impl Fn(String)) {
    use tornect_platform::win_notify::Notices;

    let mut notices: Option<Notices> = None;
    let mut tried = false;
    while let Some(change) = changes.recv().await {
        match change {
            NoticeChange::Show { sheet, asks } => {
                if !tried {
                    tried = true;
                    match tokio::task::spawn_blocking(Notices::start).await {
                        Ok(Ok(started)) => notices = Some(started),
                        Ok(Err(e)) => note(format!(
                            "the desktop notification of a request could not be shown: {e}"
                        )),
                        Err(e) => note(format!(
                            "the desktop notification of a request could not be shown: {e}"
                        )),
                    }
                }
                if let Some(notices) = &notices {
                    let (summary, body) = asks.lines();
                    notices.show(icon_id(sheet), summary, body);
                }
            }
            NoticeChange::Close { sheet } => {
                if let Some(notices) = &notices {
                    notices.remove(icon_id(sheet));
                }
            }
        }
    }
}

/// Show and take down the notifications as `changes` say, until `changes`
/// ends, on the bus that `connect` reaches at the first one. A bus that
/// cannot be reached, or a notification that cannot be shown, is said once
/// through `note` (the window's recent activity); the sheets raise the window
/// all the same.
#[cfg(target_os = "linux")]
pub async fn mirror<C, F>(
    connect: C,
    mut changes: mpsc::UnboundedReceiver<NoticeChange>,
    note: impl Fn(String),
) where
    C: FnOnce() -> F,
    F: Future<
        Output = Result<
            Arc<dyn tornect_platform::notify::NotificationBus>,
            tornect_platform::notify::NotifyError,
        >,
    >,
{
    use std::collections::HashMap;

    use tornect_platform::notify::{Shown, mirror_notice};

    let mut connect = Some(connect);
    let mut bus = None;
    let mut shown: HashMap<u64, Shown> = HashMap::new();
    let mut said = false;
    let mut say = |e: &dyn std::fmt::Display| {
        if !said {
            said = true;
            note(format!(
                "the desktop notification of a request could not be shown: {e}"
            ));
        }
    };
    while let Some(change) = changes.recv().await {
        match change {
            NoticeChange::Show { sheet, asks } => {
                if let Some(connect) = connect.take() {
                    match connect().await {
                        Ok(reached) => bus = Some(reached),
                        Err(e) => say(&e),
                    }
                }
                let Some(bus) = &bus else { continue };
                let (summary, body) = asks.lines();
                match Shown::show(Arc::clone(bus), &mirror_notice(summary, body)).await {
                    Ok(on_screen) => {
                        shown.insert(sheet, on_screen);
                    }
                    Err(e) => say(&e),
                }
            }
            NoticeChange::Close { sheet } => {
                shown.remove(&sheet);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use tornect_core::DeviceIdentity;
    use tornect_core::words::{Role, derive};

    use super::*;

    /// §B.6.1 W-B4 (no device words in notifications) and §B.1.1: whatever a
    /// host sheet shows (the declared name, the pinned label, the key's
    /// fingerprint, the code, the device words), its notification says none
    /// of it: one of two fixed texts, chosen by what the sheet asks. On Linux
    /// the notification has no action and no sound, and no time limit of its
    /// own: it goes with its sheet.
    #[test]
    fn the_notification_carries_no_words_or_name() {
        let device = DeviceIdentity::from_seed(&[8; 32]).id();
        let words = derive(device.public_key_bytes(), Role::Device).words();
        let fingerprint = device.fingerprint();
        let sheets = [
            PopupKind::Pairing {
                name: "Ana's phone".to_owned(),
                fingerprint: fingerprint.clone(),
                sas: "123 456".to_owned(),
                pinned: Some("Phone of Ana".to_owned()),
            },
            PopupKind::Session {
                label: "Laptop-of-Ana".to_owned(),
                fingerprint: fingerprint.clone(),
            },
            PopupKind::Ask {
                label: "Laptop-of-Ana".to_owned(),
                administrator: true,
            },
        ];
        let mut said = Vec::new();
        for kind in &sheets {
            let (summary, body) = Asks::of(kind).lines();
            let text = format!("{summary} {body}");
            for named in [
                "Ana",
                "phone",
                "Laptop",
                fingerprint.as_str(),
                "123",
                "456",
                words.shown().as_str(),
            ] {
                assert!(!text.contains(named), "{text:?} carries {named:?}");
            }
            said.push(text);
        }
        assert_eq!(
            said,
            [
                "A device asks to pair with this computer. Open Tornect to answer.",
                "A device asks to connect to this computer. Open Tornect to answer.",
                "A device asks to connect to this computer. Open Tornect to answer.",
            ]
        );
        // One notification per sheet, as the sheets come and go.
        let popup = |id, kind: &PopupKind| Popup {
            id,
            kind: kind.clone(),
            deadline: Instant::now(),
        };
        let mut notices = Notices::default();
        assert_eq!(notices.sync(&[]), vec![]);
        assert_eq!(
            notices.sync(&[popup(1, &sheets[0]), popup(2, &sheets[2])]),
            vec![
                NoticeChange::Show {
                    sheet: 1,
                    asks: Asks::Pair
                },
                NoticeChange::Show {
                    sheet: 2,
                    asks: Asks::Connect
                }
            ]
        );
        assert_eq!(
            notices.sync(&[popup(2, &sheets[2])]),
            vec![NoticeChange::Close { sheet: 1 }]
        );
        assert_eq!(notices.sync(&[]), vec![NoticeChange::Close { sheet: 2 }]);
        #[cfg(target_os = "linux")]
        for kind in &sheets {
            let (summary, body) = Asks::of(kind).lines();
            let notice = tornect_platform::notify::mirror_notice(summary, body);
            assert!(notice.actions.is_empty());
            assert_eq!(notice.sound, None);
            assert_eq!(notice.expire_ms, 0);
        }
    }
}
