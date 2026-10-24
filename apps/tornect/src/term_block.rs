//! The terminal host's block window (`docs/PLAN.md` §B.8.6.3, the minimal shell
//! of the M4 row; decision M1-68): before an unattended session starts,
//! `tornect host` in a terminal prints a line naming the device and the seconds
//! left, and `block` typed there refuses the request (`BLOCKED_BY_LOCAL_USER`;
//! the gate suspends the grant, `Suspended{LocalBlock}`, until a local
//! *Resume*). On Linux the window host's desktop notification comes with it,
//! and its Block does the same. The window lasts exactly the grant's
//! `block_window_s`, whether or not anyone is there; it ending without Block is
//! the veto passing, not consent (§B.8.1).
//!
//! The terminal is shared with the pairing and session questions, and a
//! question from any peer can hold it for its whole timeout. The block window
//! never waits behind one: it takes the terminal first
//! ([`Prompter::priority`]), which cancels the open question (answered as a
//! closed terminal answers it, a refusal), prints its line at once, and reads
//! the lines typed from then on until its seconds end.
//!
//! Two unattended requests can overlap, each with its window. The lines go to
//! the window that opened first, and a typed line cannot say which request it
//! means, so one `block` blocks every window open then, each saying so; a
//! window that opens beside another says that too (audit B20).
//!
//! It fails closed (OP-13): standard input ending, or a line that cannot be
//! written, before the seconds end is a Block, as a closed terminal denies a
//! question (`prompt`). Nothing more is printed then, as there is no terminal
//! to print to; the gate logs the block as any other.

use std::io::Write as _;
use std::sync::Arc;
use std::time::Duration;

use tornect_core::DeviceId;
use tornect_core::unattended::store::GrantStore;
use tornect_signal::consent::{BlockOutcome, BlockWindow, GrantId, WindowPassed};
use tornect_signal::pairing::BoxFuture;

use crate::prompt::Prompter;

/// What is typed to block (any case; spaces around it ignored).
const BLOCK_WORD: &str = "block";

/// The line the window prints for `label`'s request, `secs` before it starts.
fn block_line(label: &str, secs: u8) -> String {
    format!(
        "Unattended session from {label} starts in {secs} s. Type block and press Enter to block \
         it."
    )
}

/// The line a window adds when it opens beside others (`open` in all, itself
/// included): the lines typed cannot say which request they mean, so one
/// `block` blocks every one of them (B20).
fn several_line(open: u32) -> String {
    format!("{open} unattended requests are waiting. Typing block blocks all of them.")
}

/// The line after a Block, with the command that resumes the device.
///
/// The command names the device by its fingerprint (audit B23): unique,
/// made of hex digits and dashes only, so it reaches `tornect unattended
/// resume` as one argument from any shell, and `resolve_device` takes it.
/// A label never goes into the command: the default names have a space
/// ("Windows PC"), and a second one a parenthesis ("Windows PC (2)").
/// Where the device cannot be found, the line says where its fingerprint
/// is listed.
pub(crate) fn blocked_line(label: &str, device: Option<&DeviceId>) -> String {
    match device {
        Some(device) => format!(
            "Blocked. {label} stays suspended until you resume it here (tornect unattended \
             resume {}).",
            device.fingerprint()
        ),
        None => format!(
            "Blocked. {label} stays suspended until you resume it here (tornect unattended \
             resume with its fingerprint, which tornect devices lists)."
        ),
    }
}

/// The device a grant belongs to.
type DeviceOf = Arc<dyn Fn(&GrantId) -> Option<DeviceId> + Send + Sync>;

/// The device of grant `id` in `store`; `None` when the store holds no such
/// grant (or cannot be read).
pub(crate) fn device_of_grant(store: &GrantStore, id: &GrantId) -> Option<DeviceId> {
    store
        .read(|s| s.grants.iter().find(|g| g.id == *id).map(|g| g.device))
        .flatten()
}

/// Where the window's lines go: one line, written and flushed.
type Say = Arc<dyn Fn(&str) -> std::io::Result<()> + Send + Sync>;

/// The terminal's standard error, where the questions are asked too.
fn to_stderr(line: &str) -> std::io::Result<()> {
    let mut err = std::io::stderr().lock();
    writeln!(err, "{line}")?;
    err.flush()
}

/// Whether the desktop notification goes with the line.
enum Notify {
    /// None: every system but Linux, and the tests, which must not reach the
    /// session bus of the machine running them.
    Off,
    /// The user's session bus.
    #[cfg(target_os = "linux")]
    SessionBus,
    /// The bus a test gives.
    #[cfg(all(test, target_os = "linux"))]
    Bus(Arc<dyn tornect_platform::notify::NotificationBus>),
}

/// How the window ended before its seconds were up.
enum Ended {
    /// `block` was typed.
    Typed,
    /// The notification's Block was pressed.
    Notification,
    /// Standard input ended.
    Closed,
}

/// The terminal host's [`BlockWindow`].
pub struct TerminalBlockWindow {
    prompter: Arc<Prompter>,
    say: Say,
    notify: Notify,
    /// Names the blocked device in the resume command; `None` before
    /// [`TerminalBlockWindow::with_grants`].
    device_of: Option<DeviceOf>,
}

impl std::fmt::Debug for TerminalBlockWindow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TerminalBlockWindow")
            .finish_non_exhaustive()
    }
}

impl TerminalBlockWindow {
    /// The window on `prompter`'s terminal, with the desktop notification on
    /// Linux.
    #[must_use]
    pub fn new(prompter: Arc<Prompter>) -> Self {
        #[cfg(target_os = "linux")]
        let notify = if cfg!(test) {
            Notify::Off
        } else {
            Notify::SessionBus
        };
        #[cfg(not(target_os = "linux"))]
        let notify = Notify::Off;
        Self {
            prompter,
            say: Arc::new(to_stderr),
            notify,
            device_of: None,
        }
    }

    /// The line after a Block names the device's fingerprint, found by its
    /// grant in `store` (B23).
    #[must_use]
    pub fn with_grants(mut self, store: GrantStore) -> Self {
        self.device_of = Some(Arc::new(move |id: &GrantId| device_of_grant(&store, id)));
        self
    }

    /// The desktop notification's Block (Linux): resolves when Block is
    /// pressed in it; pending for as long as it is polled otherwise (none
    /// sent, or none could be shown). Dropped, it takes the notification down.
    async fn notified(&self, label: &str, secs: u8) {
        #[cfg(target_os = "linux")]
        {
            use tornect_platform::notify::{
                BLOCK_ACTION, NotificationBus, SessionBus, Shown, block_notice,
            };
            let bus: Option<Arc<dyn NotificationBus>> = match &self.notify {
                Notify::Off => None,
                Notify::SessionBus => match SessionBus::connect().await {
                    Ok(bus) => Some(Arc::new(bus)),
                    Err(e) => {
                        tracing::debug!(error = %e, "no notification for the block window");
                        None
                    }
                },
                #[cfg(test)]
                Notify::Bus(bus) => Some(Arc::clone(bus)),
            };
            if let Some(bus) = bus {
                match Shown::show(bus, &block_notice(label, secs)).await {
                    Ok(mut shown) => {
                        while let Some(action) = shown.action().await {
                            if action == BLOCK_ACTION {
                                return;
                            }
                        }
                        // Nothing more can come; the notification stays up
                        // until the window ends.
                        return std::future::pending().await;
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "the block window's notification was not shown");
                    }
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = (&self.notify, label, secs);
        std::future::pending().await
    }
}

impl BlockWindow for TerminalBlockWindow {
    fn run<'a>(
        &'a self,
        secs: u8,
        who: &'a GrantId,
        label: &'a str,
    ) -> BoxFuture<'a, BlockOutcome> {
        Box::pin(async move {
            if secs == 0 {
                // `block_window_s = 0`: no window at all (the grant's choice).
                return BlockOutcome::Passed(WindowPassed::Skipped);
            }
            // Exactly `secs`, counted from when the line goes up.
            let deadline = tokio::time::Instant::now() + Duration::from_secs(u64::from(secs));
            // The terminal first: the open question is cancelled before the
            // line shows, and none is shown until the window ends.
            let mut hold = self.prompter.priority();
            if (self.say)(&block_line(label, secs)).is_err() {
                // A terminal that cannot be written refuses (OP-13).
                return BlockOutcome::Blocked;
            }
            let open = hold.open_windows();
            if open > 1 && (self.say)(&several_line(open)).is_err() {
                return BlockOutcome::Blocked;
            }
            // A `block` typed while another window holds the terminal is read
            // there, and blocks this one too (B20).
            let elsewhere = hold.blocked_by_another();
            let typed = async {
                loop {
                    match hold.next_line().await {
                        Some(line) if line.trim().eq_ignore_ascii_case(BLOCK_WORD) => {
                            hold.block_every_open_window();
                            return Ended::Typed;
                        }
                        Some(_) => {}
                        // End of input: a closed terminal denies (OP-13).
                        None => return Ended::Closed,
                    }
                }
            };
            let ended = tokio::time::timeout_at(deadline, async {
                tokio::select! {
                    ended = typed => ended,
                    () = elsewhere => Ended::Typed,
                    () = self.notified(label, secs) => Ended::Notification,
                }
            })
            .await;
            let outcome = match ended {
                Err(_) => BlockOutcome::Passed(WindowPassed::Elapsed),
                Ok(Ended::Closed) => BlockOutcome::Blocked,
                Ok(Ended::Typed | Ended::Notification) => {
                    // Said before the terminal is let go; a line that cannot
                    // be written changes nothing now.
                    let device = self.device_of.as_ref().and_then(|of| of(who));
                    let _ = (self.say)(&blocked_line(label, device.as_ref()));
                    BlockOutcome::Blocked
                }
            };
            drop(hold);
            outcome
        })
    }
}
#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use tokio::time::Instant;

    use super::*;

    const GRANT: GrantId = [1; 8];

    /// Every line the window said, in order; `fail`: each write fails.
    #[derive(Default)]
    struct Said {
        lines: Mutex<Vec<String>>,
        fail: bool,
    }

    impl Said {
        fn lines(&self) -> Vec<String> {
            self.lines.lock().unwrap().clone()
        }
    }

    /// The window on `prompter`, saying into a recorder.
    fn recorded(prompter: Arc<Prompter>, fail: bool) -> (TerminalBlockWindow, Arc<Said>) {
        let said = Arc::new(Said {
            lines: Mutex::default(),
            fail,
        });
        let into = Arc::clone(&said);
        let window = TerminalBlockWindow {
            prompter,
            say: Arc::new(move |line: &str| {
                if into.fail {
                    return Err(std::io::Error::other("the terminal is gone"));
                }
                into.lines.lock().unwrap().push(line.to_owned());
                Ok(())
            }),
            notify: Notify::Off,
            device_of: None,
        };
        (window, said)
    }

    /// Let every task that can run, run.
    async fn settle() {
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
    }

    /// §B.8.6.3: the window lasts exactly `block_window_s` when nobody
    /// blocks, and `0` is no window at all, with nothing printed.
    #[tokio::test(start_paused = true)]
    async fn the_terminal_block_window_lasts_exactly_its_seconds() {
        let (prompter, _typed) = Prompter::scripted();
        let (window, said) = recorded(prompter, false);
        let t0 = Instant::now();
        assert_eq!(
            window.run(10, &GRANT, "Laptop").await,
            BlockOutcome::Passed(WindowPassed::Elapsed)
        );
        assert_eq!(t0.elapsed(), Duration::from_secs(10));
        assert_eq!(
            said.lines(),
            vec![
                "Unattended session from Laptop starts in 10 s. Type block and press Enter to \
                 block it."
                    .to_owned()
            ]
        );
        let t1 = Instant::now();
        assert_eq!(
            window.run(0, &GRANT, "Laptop").await,
            BlockOutcome::Passed(WindowPassed::Skipped)
        );
        assert_eq!(t1.elapsed(), Duration::ZERO);
        assert_eq!(said.lines().len(), 1, "no window, no line");
    }

    /// `block` typed within the seconds refuses the session at once (any
    /// case, spaces around it ignored); another line does not.
    #[tokio::test(start_paused = true)]
    async fn typing_block_blocks() {
        let (prompter, typed) = Prompter::scripted();
        let (mut window, said) = recorded(prompter, false);
        let laptop = DeviceId::from_bytes([3; 32]);
        window.device_of = Some(Arc::new(move |id: &GrantId| {
            (*id == GRANT).then_some(laptop)
        }));
        let t0 = Instant::now();
        let running = tokio::spawn(async move { window.run(10, &GRANT, "Laptop").await });
        settle().await;
        assert_eq!(said.lines().len(), 1, "the line is up");
        typed.send("yes".to_owned()).await.unwrap();
        typed.send("".to_owned()).await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(!running.is_finished(), "another line does not block");
        typed.send("  BLOCK ".to_owned()).await.unwrap();
        assert_eq!(running.await.unwrap(), BlockOutcome::Blocked);
        assert_eq!(t0.elapsed(), Duration::from_secs(2));
        assert_eq!(
            said.lines()[1],
            format!(
                "Blocked. Laptop stays suspended until you resume it here (tornect unattended \
                 resume {}).",
                laptop.fingerprint()
            )
        );
    }

    /// B23: the resume command names the device by its fingerprint, never
    /// by its label, which can have a space or a parenthesis; where the
    /// device is not found, no command with a label is printed either.
    #[test]
    fn the_resume_command_never_carries_a_label() {
        let device = DeviceId::from_bytes([4; 32]);
        for label in ["Windows PC", "Windows PC (2)", "Linux PC", "Laptop"] {
            let line = blocked_line(label, Some(&device));
            assert!(
                line.starts_with(&format!("Blocked. {label} stays suspended")),
                "{line}"
            );
            assert!(
                line.ends_with(&format!(
                    "(tornect unattended resume {}).",
                    device.fingerprint()
                )),
                "{line}"
            );
            let unknown = blocked_line(label, None);
            assert_eq!(unknown.matches(label).count(), 1, "{unknown}");
            assert!(unknown.contains("tornect devices lists"), "{unknown}");
        }
    }

    /// B20: two windows open together (devices A and B connecting within a
    /// second): the second says that `block` blocks all of them, and one
    /// `block`, read by the first window, which holds the terminal, blocks
    /// both, each with its own line. Before the fix the first was blocked
    /// and the second ran out its seconds and started. A window that opens
    /// after that `block` is not blocked by it.
    #[tokio::test(start_paused = true)]
    async fn one_block_blocks_every_open_window() {
        let (prompter, typed) = Prompter::scripted();
        let (first, said_first) = recorded(Arc::clone(&prompter), false);
        let (second, said_second) = recorded(Arc::clone(&prompter), false);
        let t0 = Instant::now();
        let first = tokio::spawn(async move { first.run(3, &GRANT, "Desk").await });
        settle().await;
        let second = tokio::spawn(async move { second.run(3, &[2; 8], "Laptop").await });
        settle().await;
        assert_eq!(said_first.lines(), vec![block_line("Desk", 3)]);
        assert_eq!(
            said_second.lines(),
            vec![block_line("Laptop", 3), several_line(2)]
        );
        typed.send("block".to_owned()).await.unwrap();
        assert_eq!(first.await.unwrap(), BlockOutcome::Blocked);
        assert_eq!(second.await.unwrap(), BlockOutcome::Blocked);
        assert_eq!(t0.elapsed(), Duration::ZERO);
        assert_eq!(said_first.lines()[1], blocked_line("Desk", None));
        assert_eq!(said_second.lines()[2], blocked_line("Laptop", None));

        let (third, said_third) = recorded(prompter, false);
        assert_eq!(
            third.run(3, &[3; 8], "Phone").await,
            BlockOutcome::Passed(WindowPassed::Elapsed)
        );
        assert_eq!(said_third.lines(), vec![block_line("Phone", 3)]);
    }

    /// FC-2: a question open on the terminal (a pairing request from any
    /// peer can hold it for its whole timeout) never hides the block window.
    /// Its line shows at once; the question is cancelled and answered as a
    /// closed terminal answers it (`None`: a refusal), and so is one queued
    /// behind it; the next line typed is the window's. Once the window
    /// ended, a new question is asked as before. Written first: it failed
    /// while the window asked through the question queue.
    #[tokio::test(start_paused = true)]
    async fn a_pending_pairing_question_cannot_hide_the_block_window() {
        let (prompter, typed) = Prompter::scripted();
        let ask = |question: &'static str| {
            let prompter = Arc::clone(&prompter);
            tokio::spawn(async move { prompter.ask(question).await })
        };
        let open = ask("PAIRING REQUEST: a device calling itself \"Phone\" asks to pair");
        settle().await;
        let queued = ask("SESSION REQUEST: \"Tablet\" wants to connect to this computer");
        settle().await;
        let (window, said) = recorded(Arc::clone(&prompter), false);
        let running = tokio::spawn(async move { window.run(10, &GRANT, "Laptop").await });
        settle().await;
        assert_eq!(said.lines().len(), 1, "the line shows at once");
        let open = tokio::time::timeout(Duration::from_secs(1), open).await;
        assert!(
            matches!(open, Ok(Ok(None))),
            "the open question is cancelled: {open:?}"
        );
        let queued = tokio::time::timeout(Duration::from_secs(1), queued).await;
        assert!(
            matches!(queued, Ok(Ok(None))),
            "the queued question is not shown: {queued:?}"
        );
        typed.send("block".to_owned()).await.unwrap();
        let outcome = tokio::time::timeout(Duration::from_secs(1), running).await;
        assert!(
            matches!(outcome, Ok(Ok(BlockOutcome::Blocked))),
            "the window took the line: {outcome:?}"
        );
        // the terminal is the questions' again
        let next = ask("PAIRING REQUEST: again");
        settle().await;
        typed.send("yes".to_owned()).await.unwrap();
        assert_eq!(next.await.unwrap().as_deref(), Some("yes"));
    }

    /// OP-13: standard input that ends before the seconds are up refuses the
    /// session (a closed terminal denies), with nothing more printed; so does
    /// a line that cannot be written, before anything is read.
    #[tokio::test(start_paused = true)]
    async fn end_of_input_refuses_the_session() {
        let (prompter, typed) = Prompter::scripted();
        let (window, said) = recorded(prompter, false);
        let t0 = Instant::now();
        let running = tokio::spawn(async move { window.run(10, &GRANT, "Laptop").await });
        tokio::time::sleep(Duration::from_secs(3)).await;
        drop(typed);
        assert_eq!(running.await.unwrap(), BlockOutcome::Blocked);
        assert_eq!(t0.elapsed(), Duration::from_secs(3));
        assert_eq!(said.lines().len(), 1, "nothing after the line");

        let (prompter, typed) = Prompter::scripted();
        let (window, said) = recorded(prompter, true);
        typed.send("anything".to_owned()).await.unwrap();
        let t1 = Instant::now();
        assert_eq!(
            window.run(10, &GRANT, "Laptop").await,
            BlockOutcome::Blocked
        );
        assert_eq!(t1.elapsed(), Duration::ZERO);
        assert!(said.lines().is_empty());
    }

    /// Linux (§B.8.6.3, best effort where no window stays on top): the window
    /// host's notification comes with the line, and its Block blocks as the
    /// typed word does; dropped with the window, it is taken down.
    #[cfg(target_os = "linux")]
    #[tokio::test(start_paused = true)]
    async fn the_notification_block_blocks() {
        use tokio::sync::mpsc;
        use tornect_platform::notify::{Notice, NotificationBus, NotifyError, block_notice};

        #[derive(Default)]
        struct FakeBus {
            shown: Mutex<Vec<Notice>>,
            closed: Mutex<Vec<u32>>,
            invoke: Mutex<Option<mpsc::Sender<(u32, String)>>>,
        }

        impl NotificationBus for FakeBus {
            fn actions(
                &self,
            ) -> tornect_platform::polkit::BoxFuture<
                '_,
                Result<mpsc::Receiver<(u32, String)>, NotifyError>,
            > {
                let (tx, rx) = mpsc::channel(4);
                *self.invoke.lock().unwrap() = Some(tx);
                Box::pin(async move { Ok(rx) })
            }

            fn notify<'a>(
                &'a self,
                notice: &'a Notice,
            ) -> tornect_platform::polkit::BoxFuture<'a, Result<u32, NotifyError>> {
                self.shown.lock().unwrap().push(notice.clone());
                Box::pin(async { Ok(5) })
            }

            fn close(&self, id: u32) -> tornect_platform::polkit::BoxFuture<'_, ()> {
                self.closed.lock().unwrap().push(id);
                Box::pin(async {})
            }
        }

        let bus = Arc::new(FakeBus::default());
        let (prompter, _typed) = Prompter::scripted();
        let (mut window, said) = recorded(prompter, false);
        window.notify = Notify::Bus(Arc::clone(&bus) as Arc<dyn NotificationBus>);
        let t0 = Instant::now();
        let running = tokio::spawn(async move { window.run(10, &GRANT, "Laptop").await });
        settle().await;
        assert_eq!(*bus.shown.lock().unwrap(), vec![block_notice("Laptop", 10)]);
        tokio::time::sleep(Duration::from_secs(4)).await;
        let invoke = bus.invoke.lock().unwrap().clone().unwrap();
        invoke.send((4, "block".to_owned())).await.unwrap();
        settle().await;
        assert!(!running.is_finished(), "another notification's Block");
        invoke.send((5, "block".to_owned())).await.unwrap();
        assert_eq!(running.await.unwrap(), BlockOutcome::Blocked);
        assert_eq!(t0.elapsed(), Duration::from_secs(4));
        assert!(said.lines()[1].starts_with("Blocked. Laptop stays suspended"));
        settle().await;
        assert_eq!(*bus.closed.lock().unwrap(), vec![5], "taken down");
    }
}
