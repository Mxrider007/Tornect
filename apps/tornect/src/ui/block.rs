//! The block window (`docs/PLAN.md` §B.8.6.3): before an unattended session
//! starts, a Tornect window with exactly one control, **Block**, on every
//! monitor, for exactly the grant's `block_window_s`, whether or not anyone is
//! present. Block refuses the request (`BLOCKED_BY_LOCAL_USER`) and the gate
//! suspends the grant (`Suspended{LocalBlock}`) until a local *Resume*; the
//! window ending without Block is the veto passing, not consent (§B.8.1).
//!
//! The windows hang off the app's one event loop (`app`, decision D10): one
//! per monitor the desktop lists, always on top, undecorated (no close button),
//! deaf to a close request, and re-asserted every [`REASSERT`]. Wayland lets no
//! client keep its own window above the others: there each window asks for the
//! focus when it opens, and a desktop notification carries Block as an action,
//! with the chime as its sound (`tornect_platform::notify`; sent on every Linux
//! desktop, so X11 gets the chime too) — the best effort of §B.8.6.3. What the
//! compositor and the notification server make of them is NEEDS-DEVICE(gnome).
//! Elsewhere the windows do not take the focus: they are on top, and keys typed
//! for another program must not land on them.
//!
//! A window counts as shown only once it drew its first frame (the app reports
//! it where it paints the block windows), or on Linux once the notification
//! server showed the notification. A request whose block window was shown
//! nowhere before its end, or could no longer be shown anywhere, is refused
//! (`BlockOutcome::NotShown`: `HOST_NOT_READY` without a cause, the grant left
//! as it was): nobody could have pressed Block.
//!
//! Where the session may be control (the grant's mode, lowered by the
//! request) and the saved settings give it the clipboard or files, the
//! window says so in one fixed line (the services design §7.4).
//!
//! The terminal host (`tornect host`) has no such window: it keeps the headless
//! seams, so nobody can press Block there and every "Ask before starting" is
//! denied (the minimal shell of M4 is not built in M-FEAT-5).

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::watch;
use tornect_core::session_log::SessionMode;
use tornect_signal::consent::{BlockOutcome, BlockWindow, GrantId, WindowPassed};
use tornect_signal::pairing::BoxFuture;
use winit::dpi::{LogicalSize, PhysicalPosition, PhysicalSize};
use winit::window::{Window, WindowAttributes, WindowLevel};

use super::consent::{BlockSurfaces, Popups};

/// The windows' title: what Alt+Tab, the overview and the taskbar show. It
/// names no device, as the indicator's does not.
pub const TITLE: &str = "Tornect: unattended session starting";
/// How often each window is put back on top, shown and restored.
pub const REASSERT: Duration = Duration::from_millis(500);
/// Width, in logical pixels.
const WIDTH: f64 = 460.0;
/// Height, in logical pixels: room for the line of what control also gives
/// (the services design §7.4) under the countdown of a label of the most
/// characters a label may have, with Block and the bottom margin whole.
const HEIGHT: f64 = 232.0;

/// The window's size, in logical pixels (fixed: the user cannot resize it).
#[must_use]
pub fn size() -> LogicalSize<f64> {
    LogicalSize::new(WIDTH, HEIGHT)
}

/// The top-left corner that centres a window of `window` logical pixels on a
/// monitor at `origin`, `extent` physical pixels wide and high, at `scale`;
/// never left of or above the monitor.
#[must_use]
pub fn centred(
    origin: PhysicalPosition<i32>,
    extent: PhysicalSize<u32>,
    scale: f64,
    window: LogicalSize<f64>,
) -> PhysicalPosition<i32> {
    let x = f64::from(origin.x) + (f64::from(extent.width) - window.width * scale) / 2.0;
    let y = f64::from(origin.y) + (f64::from(extent.height) - window.height * scale) / 2.0;
    PhysicalPosition::new(
        (x.round() as i32).max(origin.x),
        (y.round() as i32).max(origin.y),
    )
}

/// One block window as it is asked for: always on top, no decorations (so no
/// close button), a fixed size, at `position` where the desktop allows
/// placement; activated when it opens only on Wayland (`focused`), where it
/// cannot stay on top.
#[must_use]
pub fn attributes(position: Option<PhysicalPosition<i32>>, focused: bool) -> WindowAttributes {
    let mut attrs = Window::default_attributes()
        .with_title(TITLE)
        .with_inner_size(size())
        .with_resizable(false)
        .with_decorations(false)
        .with_window_level(WindowLevel::AlwaysOnTop)
        .with_active(focused);
    if let Some(position) = position {
        attrs = attrs.with_position(position);
    }
    attrs
}

/// Put `window` back (every [`REASSERT`]): on top, and shown and restored
/// where it is known to be hidden or minimised, never otherwise, since X11's
/// restore is an activation request and the window must not take the focus.
pub fn reassert(window: &Window) {
    window.set_window_level(WindowLevel::AlwaysOnTop);
    if window.is_visible() == Some(false) {
        window.set_visible(true);
    }
    if window.is_minimized() == Some(true) {
        window.set_minimized(false);
    }
}

/// The window host's [`BlockWindow`]: the windows through [`Popups`] (the app
/// opens one per monitor while the request is in the model), and on Linux the
/// desktop notification with its Block action.
pub struct GuiBlockWindow {
    popups: Arc<Popups>,
    /// Send the desktop notification (Linux; never in tests, which must not
    /// reach the session bus of the machine running them).
    notify: bool,
}

impl std::fmt::Debug for GuiBlockWindow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuiBlockWindow")
            .field("notify", &self.notify)
            .finish_non_exhaustive()
    }
}

impl GuiBlockWindow {
    /// Block windows shown through `popups`, with the desktop notification on
    /// Linux.
    #[must_use]
    pub fn new(popups: Arc<Popups>) -> Self {
        Self {
            popups,
            notify: cfg!(target_os = "linux"),
        }
    }

    /// Tests: the windows only, never the session bus of the machine running
    /// them.
    #[cfg(test)]
    pub(super) fn without_notification(popups: Arc<Popups>) -> Self {
        Self {
            popups,
            notify: false,
        }
    }
}

impl BlockWindow for GuiBlockWindow {
    /// Without the session's mode the window names no service (the state
    /// machine always says the mode, through [`BlockWindow::run_for`]).
    fn run<'a>(
        &'a self,
        secs: u8,
        who: &'a GrantId,
        label: &'a str,
    ) -> BoxFuture<'a, BlockOutcome> {
        self.run_for(secs, who, label, SessionMode::ViewOnly)
    }

    fn run_for<'a>(
        &'a self,
        secs: u8,
        _: &'a GrantId,
        label: &'a str,
        mode: SessionMode,
    ) -> BoxFuture<'a, BlockOutcome> {
        Box::pin(async move {
            if secs == 0 {
                // `block_window_s = 0`: no window at all (an explicit choice of
                // the grant, §B.8.6.1).
                return BlockOutcome::Passed(WindowPassed::Skipped);
            }
            let length = Duration::from_secs(u64::from(secs));
            // Exactly `secs`, counted from when the window is put up.
            let deadline = tokio::time::Instant::now() + length;
            let (shown, clicked, surfaces) = self.popups.open_block(
                label,
                Instant::now() + length,
                mode == SessionMode::Control,
            );
            let (notice, notice_now) = watch::channel(if self.notify {
                Notice::Pending
            } else {
                Notice::Absent
            });
            let blocked = async {
                tokio::select! {
                    Ok(()) = clicked => {}
                    () = notified(self.notify, label, secs, &notice) => {}
                    else => std::future::pending::<()>().await,
                }
            };
            // A Block at the same moment as the end or as the last failure
            // still blocks.
            let outcome = tokio::select! {
                biased;
                () = blocked => BlockOutcome::Blocked,
                () = shown_nowhere(surfaces.clone(), notice_now.clone()) => BlockOutcome::NotShown,
                () = tokio::time::sleep_until(deadline) => {
                    at_the_end(*surfaces.borrow(), *notice_now.borrow())
                }
            };
            drop(shown);
            outcome
        })
    }
}

/// The block window's desktop notification (Linux), as far as it is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Notice {
    /// Being sent.
    Pending,
    /// The notification server showed it.
    Shown,
    /// None: not sent on this system, or it could not be shown.
    Absent,
}

/// Whether the request's block window can no longer be shown anywhere: every
/// window failed to open, and no notification is up or still coming.
fn nowhere(surfaces: BlockSurfaces, notice: Notice) -> bool {
    surfaces == BlockSurfaces::Failed && notice == Notice::Absent
}

/// The outcome at the window's end without Block (§B.8.6.3): the veto passed
/// only where a window drew its first frame or the notification was shown;
/// otherwise nobody could have pressed Block, and the request is refused.
fn at_the_end(surfaces: BlockSurfaces, notice: Notice) -> BlockOutcome {
    if surfaces == BlockSurfaces::Drew || notice == Notice::Shown {
        BlockOutcome::Passed(WindowPassed::Elapsed)
    } else {
        BlockOutcome::NotShown
    }
}

/// Resolves once the request's block window can no longer be shown anywhere
/// ([`nowhere`]); pending otherwise.
async fn shown_nowhere(
    mut surfaces: watch::Receiver<BlockSurfaces>,
    mut notice: watch::Receiver<Notice>,
) {
    loop {
        let now = (*surfaces.borrow_and_update(), *notice.borrow_and_update());
        if nowhere(now.0, now.1) {
            return;
        }
        let changed = tokio::select! {
            changed = surfaces.changed() => changed,
            changed = notice.changed() => changed,
        };
        if changed.is_err() {
            // The window ended: its end decides.
            return std::future::pending().await;
        }
    }
}

/// The desktop notification's Block (Linux): resolves when Block is pressed in
/// it; pending for as long as it is polled otherwise (no notification sent, or
/// none could be shown). `notice` says whether it was shown. Dropped, it takes
/// the notification down.
async fn notified(notify: bool, label: &str, secs: u8, notice: &watch::Sender<Notice>) {
    #[cfg(target_os = "linux")]
    if notify {
        use tornect_platform::notify::{BLOCK_ACTION, SessionBus, Shown, block_notice};
        let bus = match SessionBus::connect().await {
            Ok(bus) => bus,
            Err(e) => {
                tracing::debug!(error = %e, "no notification for the block window");
                notice.send_replace(Notice::Absent);
                return std::future::pending().await;
            }
        };
        match Shown::show(Arc::new(bus), &block_notice(label, secs)).await {
            Ok(mut shown) => {
                notice.send_replace(Notice::Shown);
                while let Some(action) = shown.action().await {
                    if action == BLOCK_ACTION {
                        return;
                    }
                }
                // Nothing more can come; the notification stays up until the
                // window ends.
                return std::future::pending().await;
            }
            Err(e) => {
                tracing::debug!(error = %e, "the block window's notification was not shown");
                notice.send_replace(Notice::Absent);
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (notify, label, secs, notice);
    std::future::pending().await
}

#[cfg(test)]
mod tests {
    use super::super::model::{Model, Shared};
    use super::*;

    fn window() -> (Arc<Popups>, GuiBlockWindow) {
        let popups = Popups::new(Shared::new(Model::default(), Arc::new(|_| {})));
        let block = GuiBlockWindow {
            popups: Arc::clone(&popups),
            notify: false,
        };
        (popups, block)
    }

    fn shown(popups: &Popups) -> Vec<String> {
        popups
            .shared()
            .read(|m| m.blocks.iter().map(|b| b.label.clone()).collect())
    }

    /// §B.8.6.3: the window lasts exactly `block_window_s`, up the whole time,
    /// and then the request goes on (`Elapsed`, never consent); at 0 there is no
    /// window at all.
    #[tokio::test(start_paused = true)]
    async fn the_block_window_lasts_exactly_its_seconds() {
        let (popups, block) = window();
        popups.draw_blocks_at_once();
        let run = tokio::spawn({
            let block = GuiBlockWindow {
                popups: Arc::clone(&popups),
                notify: false,
            };
            async move { block.run(10, &[7; 8], "Laptop").await }
        });
        drop(block);
        tokio::time::sleep(Duration::from_millis(9_999)).await;
        assert_eq!(shown(&popups), vec!["Laptop".to_owned()], "up at 9.999 s");
        assert!(!run.is_finished(), "not over before its seconds");
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert_eq!(
            run.await.unwrap(),
            BlockOutcome::Passed(WindowPassed::Elapsed)
        );
        assert!(shown(&popups).is_empty(), "down when it ends");

        let (popups, block) = window();
        assert_eq!(
            block.run(0, &[7; 8], "Laptop").await,
            BlockOutcome::Passed(WindowPassed::Skipped)
        );
        assert!(shown(&popups).is_empty(), "no window at 0 s");
    }

    /// §B.8.6.3: a block window shown nowhere refuses the request
    /// (`NotShown`), never lets it through: with no report from the app (which
    /// reports nothing when it creates a window, only its first frame), at the
    /// window's end and not before; when every window failed to open, at once.
    /// The rule: only a window that drew or a notification that was shown lets
    /// the veto pass.
    #[tokio::test(start_paused = true)]
    async fn a_block_window_shown_nowhere_refuses_the_request() {
        let (popups, block) = window();
        let run = tokio::spawn(async move { block.run(10, &[7; 8], "Laptop").await });
        tokio::time::sleep(Duration::from_millis(9_999)).await;
        assert_eq!(shown(&popups), vec!["Laptop".to_owned()], "up at 9.999 s");
        assert!(!run.is_finished(), "not over before its seconds");
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert_eq!(run.await.unwrap(), BlockOutcome::NotShown);
        assert!(shown(&popups).is_empty(), "down when it ends");

        let (popups, block) = window();
        let started = tokio::time::Instant::now();
        let run = tokio::spawn(async move { block.run(10, &[7; 8], "Laptop").await });
        tokio::time::sleep(Duration::from_secs(1)).await;
        let id = popups.shared().read(|m| m.blocks[0].id);
        popups.block_failed(id);
        assert_eq!(run.await.unwrap(), BlockOutcome::NotShown);
        assert!(started.elapsed() < Duration::from_secs(2), "at once");
        assert!(shown(&popups).is_empty());

        use BlockSurfaces::{Drew, Failed, Waiting};
        let passed = BlockOutcome::Passed(WindowPassed::Elapsed);
        let refused = BlockOutcome::NotShown;
        for (surfaces, notice, end, gone) in [
            (Waiting, Notice::Absent, refused, false),
            (Waiting, Notice::Pending, refused, false),
            (Waiting, Notice::Shown, passed, false),
            (Drew, Notice::Absent, passed, false),
            (Drew, Notice::Pending, passed, false),
            (Failed, Notice::Absent, refused, true),
            (Failed, Notice::Pending, refused, false),
            (Failed, Notice::Shown, passed, false),
        ] {
            assert_eq!(at_the_end(surfaces, notice), end, "{surfaces:?} {notice:?}");
            assert_eq!(nowhere(surfaces, notice), gone, "{surfaces:?} {notice:?}");
        }
    }

    /// Block, pressed in the window before its end, refuses at once; the window
    /// goes, and a late Block finds nothing to answer.
    #[tokio::test(start_paused = true)]
    async fn block_in_the_window_refuses_at_once() {
        let (popups, block) = window();
        let run = tokio::spawn(async move { block.run(10, &[7; 8], "Laptop").await });
        tokio::time::sleep(Duration::from_secs(3)).await;
        let id = popups.shared().read(|m| m.blocks[0].id);
        assert!(popups.answer_block(id));
        assert_eq!(run.await.unwrap(), BlockOutcome::Blocked);
        assert!(shown(&popups).is_empty());
        assert!(!popups.answer_block(id), "nothing left to block");
    }

    /// The services design §7.4: the window says what control also gives
    /// only where the session may be control (the mode the state machine
    /// gives `run_for`; `run` gives none) and the saved settings give this
    /// computer's clipboard or files; on a Wayland desktop whose portal is
    /// not asked for its clipboard, the clipboard alone does not count.
    #[tokio::test(start_paused = true)]
    async fn the_window_says_what_control_also_gives_only_where_it_may() {
        use super::super::model::Setup;
        use tornect_core::config::Services;

        let off = Services {
            clipboard: false,
            receive_files: false,
            browse_files: false,
            ..Services::default()
        };
        let clipboard_only = Services {
            clipboard: true,
            ..off
        };
        let wayland = Some(Setup {
            token_file: std::path::PathBuf::from("token"),
            granted: true,
            busy: false,
            note: None,
        });
        for (mode, services, setup, said) in [
            (Some(SessionMode::Control), Services::default(), None, true),
            (
                Some(SessionMode::ViewOnly),
                Services::default(),
                None,
                false,
            ),
            (None, Services::default(), None, false),
            (Some(SessionMode::Control), off, None, false),
            (Some(SessionMode::Control), clipboard_only, None, true),
            (
                Some(SessionMode::Control),
                clipboard_only,
                wayland.clone(),
                false,
            ),
            (
                Some(SessionMode::Control),
                Services::default(),
                wayland.clone(),
                true,
            ),
        ] {
            let (popups, block) = window();
            popups.shared().update(|m| {
                m.settings.services = services;
                m.setup.clone_from(&setup);
            });
            let run = tokio::spawn(async move {
                match mode {
                    Some(mode) => block.run_for(10, &[7; 8], "Laptop", mode).await,
                    None => block.run(10, &[7; 8], "Laptop").await,
                }
            });
            tokio::time::sleep(Duration::from_secs(1)).await;
            let told = popups.shared().read(|m| m.blocks[0].services);
            assert_eq!(told, said, "{mode:?} {services:?} {:?}", setup.is_some());
            let id = popups.shared().read(|m| m.blocks[0].id);
            assert!(popups.answer_block(id));
            assert_eq!(run.await.unwrap(), BlockOutcome::Blocked);
        }
    }

    /// Each window sits on top, undecorated (no close button), at a fixed size,
    /// centred on its monitor; only on Wayland does it ask for the focus.
    #[test]
    fn the_window_is_on_top_without_a_close_button() {
        for focused in [false, true] {
            let attrs = attributes(Some(PhysicalPosition::new(10, 20)), focused);
            assert_eq!(attrs.window_level, WindowLevel::AlwaysOnTop);
            assert!(!attrs.decorations);
            assert!(!attrs.resizable);
            assert_eq!(attrs.active, focused);
            assert_eq!(attrs.title, TITLE);
        }
        assert_eq!(
            centred(
                PhysicalPosition::new(1920, 0),
                PhysicalSize::new(1920, 1080),
                1.0,
                size()
            ),
            PhysicalPosition::new(1920 + 730, 424)
        );
        // A monitor smaller than the window: never off its top-left corner.
        assert_eq!(
            centred(
                PhysicalPosition::new(0, 0),
                PhysicalSize::new(300, 100),
                2.0,
                size()
            ),
            PhysicalPosition::new(0, 0)
        );
    }
}
