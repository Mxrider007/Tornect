//! The secure-desktop notice (`docs/PLAN.md` §B.8.8; r7, M-FEAT-3): while a
//! Control session is shared, the host watches whether Windows switched the
//! input desktop to a secure screen — a UAC prompt, the Ctrl+Alt+Del screen,
//! the lock screen — which no input from a user-session process reaches
//! (`OpenInputDesktop` refuses such a desktop, or names another than
//! `Default`).
//!
//! The notice's words are [`NOTICE`]. Where it goes in this build: the
//! host's own window lists it with the session's events, and the log. It
//! does not reach the viewer: the media protocol has no notice message and
//! the `ctrl` stream of §B.2 is not built, and adding either is a wire change
//! (the viewer's line is M-UI-4's). The probe is Windows-only
//! (NEEDS-DEVICE(windows)); the watch is tested here over a fake.
// The hosts start the watch on Windows only; the watch itself is tested on
// every system.
#![cfg_attr(not(windows), allow(dead_code))]

use std::sync::Arc;
use std::time::Duration;

/// What the viewer is to be told (§B.8.8).
pub const NOTICE: &str =
    "The computer is showing a secure Windows screen; the person there must answer it";

/// Said when the secure screen is gone again.
pub const NOTICE_GONE: &str = "The secure Windows screen closed";

/// How often the input desktop is looked at.
pub const EVERY: Duration = Duration::from_secs(1);

/// The input desktop: Windows' `OpenInputDesktop`, or a fake in tests.
pub trait InputDesktop: Send + Sync {
    /// Whether a secure screen is the input desktop; `None` when that could
    /// not be read.
    fn secure(&self) -> Option<bool>;
}

/// Windows' input desktop (NEEDS-DEVICE(windows)).
#[cfg(windows)]
pub struct WindowsDesktop;

#[cfg(windows)]
impl InputDesktop for WindowsDesktop {
    fn secure(&self) -> Option<bool> {
        tornect_platform::helper::secure_desktop_shown()
    }
}

/// Readings in, changes out: `Some(true)` once when a secure screen
/// appears, `Some(false)` once when it goes; an unreadable reading changes
/// nothing.
#[derive(Debug, Default)]
pub struct Watch {
    shown: bool,
}

impl Watch {
    /// The change `reading` makes, if any.
    pub fn read(&mut self, reading: Option<bool>) -> Option<bool> {
        match reading {
            Some(now) if now != self.shown => {
                self.shown = now;
                Some(now)
            }
            _ => None,
        }
    }
}

/// Look at `desktop` every `every` while `live()` holds; `told(true)` when a
/// secure screen appears, `told(false)` when it goes (and once more at the
/// end if it was still shown).
pub async fn run(
    desktop: Arc<dyn InputDesktop>,
    every: Duration,
    live: impl Fn() -> bool,
    told: impl Fn(bool),
) {
    let mut watch = Watch::default();
    let mut tick = tokio::time::interval(every);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        if !live() {
            if watch.read(Some(false)).is_some() {
                told(false);
            }
            return;
        }
        if let Some(change) = watch.read(desktop.secure()) {
            told(change);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    #[test]
    fn a_change_is_told_once_and_an_unreadable_desktop_changes_nothing() {
        let mut w = Watch::default();
        assert_eq!(w.read(Some(false)), None);
        assert_eq!(w.read(None), None);
        assert_eq!(w.read(Some(true)), Some(true));
        assert_eq!(w.read(Some(true)), None);
        assert_eq!(w.read(None), None, "unreadable: still shown");
        assert_eq!(w.read(Some(false)), Some(false));
        assert_eq!(w.read(Some(false)), None);
    }

    /// A fake desktop that plays a script of readings.
    struct Script(Mutex<Vec<Option<bool>>>);

    impl InputDesktop for Script {
        fn secure(&self) -> Option<bool> {
            let mut s = self.0.lock().unwrap();
            if s.len() > 1 { s.remove(0) } else { s[0] }
        }
    }

    /// The watch over a fake: the notice when the secure screen appears,
    /// its end when it goes, and at the session's end if still shown.
    #[tokio::test(start_paused = true)]
    async fn the_watch_tells_the_secure_screen_while_the_session_lives() {
        let desktop = Arc::new(Script(Mutex::new(vec![
            Some(false),
            Some(true),
            None,
            Some(true),
            Some(false),
            Some(true),
        ])));
        let told = Arc::new(Mutex::new(Vec::new()));
        let live = Arc::new(AtomicBool::new(true));
        let task = {
            let (told, live) = (Arc::clone(&told), Arc::clone(&live));
            tokio::spawn(async move {
                run(
                    desktop,
                    EVERY,
                    move || live.load(Ordering::SeqCst),
                    move |c| told.lock().unwrap().push(c),
                )
                .await;
            })
        };
        tokio::time::sleep(EVERY * 7).await;
        live.store(false, Ordering::SeqCst);
        tokio::time::sleep(EVERY * 2).await;
        task.await.unwrap();
        assert_eq!(*told.lock().unwrap(), vec![true, false, true, false]);
        assert!(NOTICE.starts_with("The computer is showing a secure Windows screen"));
    }
}
