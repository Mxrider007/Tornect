//! The secure-desktop notice (`docs/PLAN.md` §B.8.8; r7, M-FEAT-3): while a
//! Control session is shared, the host watches whether Windows switched the
//! input desktop to a secure screen — a UAC prompt, the Ctrl+Alt+Del screen,
//! the lock screen — which no input from a user-session process reaches
//! (`OpenInputDesktop` refuses such a desktop, or names another than
//! `Default`).
//!
//! The notice's words are [`NOTICE`]: the host's own window lists it with
//! the session's events, and its terminal and its log say it. The host also
//! tells the viewer, as bit 0x04 of the notice code its `PONG` carries
//! (decision M1-70, §B.8.4.1), and the viewer says its own sentence from
//! that number. With the same code every Control session's viewer learns at
//! the start whether the host runs Windows and whether the session's input
//! can reach windows that run as administrator ([`start_code`]); a
//! view-only session's viewer is told nothing. The probe is Windows-only
//! (NEEDS-DEVICE(windows)); the watch and the code are tested here over
//! fakes.
// The hosts start the watch on Windows only; the watch itself is tested on
// every system.
#![cfg_attr(not(windows), allow(dead_code))]

use std::sync::Arc;
use std::time::Duration;

use tornect_core::levels::Elevation;
use tornect_core::session_log::SessionMode;
use tornect_signal::fsm::host::{LiveSession, LiveSessions};
use tornect_signal::messages::notice;

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

/// The notice code a session's viewer is told at its start (decision M1-70,
/// §B.8.4.1): nothing in a view-only session; in a Control session always a
/// code, 0 included, so the viewer knows the host said it: on a Windows host
/// [`notice::WINDOWS`], with [`notice::NO_ADMIN_WINDOWS`] when the level
/// signed in the accept is none, since the session's input then cannot reach
/// windows that run as administrator (UIPI, §B.2.1). The signed level is the
/// one that counts: a host started elevated with UAC on refuses to serve, and
/// where control is administrator in effect no answer offers plain Allow.
#[must_use]
pub fn start_code(windows: bool, mode: SessionMode, elevation: Elevation) -> Option<u8> {
    if mode != SessionMode::Control {
        return None;
    }
    Some(match (windows, elevation) {
        (false, _) => 0,
        (true, Elevation::Admin) => notice::WINDOWS,
        (true, Elevation::None) => notice::WINDOWS | notice::NO_ADMIN_WINDOWS,
    })
}

/// A session went live: its start code, when it has one, is what `live`
/// tells its viewer from the first `PONG` on.
pub fn on_start(live: &LiveSessions, session: &LiveSession<'_>, windows: bool) {
    if let Some(code) = start_code(windows, session.mode, session.elevation) {
        live.set_notice(session.session_id, code);
    }
}

/// The watch saw a secure screen appear (`shown`) or go during session
/// `id`: the bit its viewer is told follows, and the line for the host's
/// window, terminal and log is returned.
pub fn on_change(live: &LiveSessions, id: &str, shown: bool) -> &'static str {
    live.set_notice_bits(id, notice::SECURE_SCREEN, shown);
    if shown { NOTICE } else { NOTICE_GONE }
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

    /// `f` over a session live in a fresh `LiveSessions`, at `mode` and
    /// `elevation`.
    fn with_session(
        mode: SessionMode,
        elevation: Elevation,
        f: impl FnOnce(&LiveSessions, &LiveSession<'_>),
    ) {
        use tornect_signal::fsm::host::SessionSink as _;
        let live = LiveSessions::new();
        let token = tornect_signal::consent::SessionToken::new([5; 32]);
        let id = token.session_id();
        let session = LiveSession {
            device: tornect_core::DeviceId::from_bytes([5; 32]),
            label: "Desk",
            session_id: &id,
            token: &token,
            th_final: [0; 32],
            mode,
            elevation,
            unattended: false,
        };
        live.on_start(&session);
        f(&live, &session);
    }

    /// What a session's viewer is told at its start: nothing in view-only;
    /// in control 0 on a host that does not run Windows, the Windows bit on a
    /// Windows host, and the administrator-windows bit with it only when the
    /// signed level is none.
    #[test]
    fn the_start_code_says_windows_and_the_line_only_for_control_without_administrator() {
        assert_eq!(
            (
                notice::WINDOWS,
                notice::NO_ADMIN_WINDOWS,
                notice::SECURE_SCREEN
            ),
            (0x01, 0x02, 0x04)
        );
        for windows in [false, true] {
            for elevation in [Elevation::None, Elevation::Admin] {
                assert_eq!(start_code(windows, SessionMode::ViewOnly, elevation), None);
                let want = match (windows, elevation) {
                    (false, _) => 0,
                    (true, Elevation::None) => 0x03,
                    (true, Elevation::Admin) => 0x01,
                };
                assert_eq!(
                    start_code(windows, SessionMode::Control, elevation),
                    Some(want),
                    "windows {windows}, {elevation:?}"
                );
            }
        }
    }

    /// A view-only session's viewer is told nothing, at its start or when a
    /// secure screen shows.
    #[test]
    fn a_view_only_session_gets_no_notice() {
        use tornect_signal::fsm::host::SessionSink as _;
        for windows in [false, true] {
            with_session(SessionMode::ViewOnly, Elevation::None, |live, session| {
                on_start(live, session, windows);
                assert_eq!(live.notice(session.session_id), None);
                on_change(live, session.session_id, true);
                assert_eq!(live.notice(session.session_id), None);
            });
        }
    }

    /// The start code lands in the session's entry, for every platform,
    /// mode and level.
    #[test]
    fn on_start_sets_the_sessions_code() {
        use tornect_signal::fsm::host::SessionSink as _;
        for windows in [false, true] {
            for mode in [SessionMode::Control, SessionMode::ViewOnly] {
                for elevation in [Elevation::None, Elevation::Admin] {
                    let want = match (windows, mode, elevation) {
                        (_, SessionMode::ViewOnly, _) => None,
                        (false, SessionMode::Control, _) => Some(0x00),
                        (true, SessionMode::Control, Elevation::None) => Some(0x03),
                        (true, SessionMode::Control, Elevation::Admin) => Some(0x01),
                    };
                    with_session(mode, elevation, |live, session| {
                        on_start(live, session, windows);
                        assert_eq!(
                            live.notice(session.session_id),
                            want,
                            "windows {windows}, {mode:?}, {elevation:?}"
                        );
                    });
                }
            }
        }
    }

    /// The watch's changes set and clear the secure-screen bit of a Control
    /// session's code, and give the host's own two lines.
    #[test]
    fn on_change_sets_and_clears_the_secure_screen_bit() {
        use tornect_signal::fsm::host::SessionSink as _;
        for (windows, start) in [(false, 0), (true, 0x03)] {
            with_session(SessionMode::Control, Elevation::None, |live, session| {
                let id = session.session_id;
                on_start(live, session, windows);
                assert_eq!(live.notice(id), Some(start));
                assert_eq!(on_change(live, id, true), NOTICE);
                assert_eq!(live.notice(id), Some(start | 0x04));
                assert_eq!(on_change(live, id, false), NOTICE_GONE);
                assert_eq!(live.notice(id), Some(start));
            });
        }
        assert_eq!(NOTICE_GONE, "The secure Windows screen closed");
    }

    /// The watch over the fake desktop, told through `on_change`: the bit the
    /// viewer reads follows the secure screen, and clears at the end.
    #[tokio::test(start_paused = true)]
    async fn the_secure_screen_bit_follows_the_watch() {
        use tornect_signal::fsm::host::SessionSink as _;
        let live = Arc::new(LiveSessions::new());
        let token = tornect_signal::consent::SessionToken::new([6; 32]);
        let id = token.session_id();
        live.on_start(&LiveSession {
            device: tornect_core::DeviceId::from_bytes([6; 32]),
            label: "Desk",
            session_id: &id,
            token: &token,
            th_final: [0; 32],
            mode: SessionMode::Control,
            elevation: Elevation::None,
            unattended: false,
        });
        live.set_notice(
            &id,
            start_code(true, SessionMode::Control, Elevation::None).unwrap(),
        );
        let desktop = Arc::new(Script(Mutex::new(vec![
            Some(false),
            Some(true),
            None,
            Some(true),
            Some(false),
            Some(true),
        ])));
        let told = Arc::new(Mutex::new(Vec::new()));
        let going = Arc::new(AtomicBool::new(true));
        let task = {
            let (told, going, live, id) = (
                Arc::clone(&told),
                Arc::clone(&going),
                Arc::clone(&live),
                id.clone(),
            );
            tokio::spawn(async move {
                run(
                    desktop,
                    EVERY,
                    move || going.load(Ordering::SeqCst),
                    move |shown| {
                        let line = on_change(&live, &id, shown);
                        told.lock().unwrap().push((line, live.notice(&id)));
                    },
                )
                .await;
            })
        };
        tokio::time::sleep(EVERY * 7).await;
        going.store(false, Ordering::SeqCst);
        tokio::time::sleep(EVERY * 2).await;
        task.await.unwrap();
        assert_eq!(
            *told.lock().unwrap(),
            vec![
                (NOTICE, Some(0x07)),
                (NOTICE_GONE, Some(0x03)),
                (NOTICE, Some(0x07)),
                (NOTICE_GONE, Some(0x03)),
            ]
        );
    }
}
