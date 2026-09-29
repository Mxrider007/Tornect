//! The host's side of the administrator helper (`docs/PLAN.md` §B.2.1,
//! §B.8.7.5; r7, M-FEAT-3).
//!
//! After an answer "Allow as administrator" that needs the helper, the host
//! FSM asks [`AdminHelpers::start`], between the answer and the accept. On
//! Windows that creates the session's pipe (explicit DACL, one instance,
//! 128 random bits in its name), starts `tornect input-helper` through
//! Windows' prompt (`ShellExecuteExW`, verb `runas`) with the pipe's name and
//! this process's id, and waits at most [`BUDGET`](tornect_platform::helper::BUDGET)
//! after Windows started it for the one client to connect, pass the check
//! (the process Windows started) and say it is ready. Only then does the
//! accept carry the administrator level; a helper later than that is ended
//! and never attached. Once the accept went out, [`Attached::attach`] keeps
//! the link for the session, and the session's input goes to the helper
//! ([`AdminBackend`]); its end stops the helper. The helper's panic chord,
//! or its going away, ends the session through the host's kill path.
//!
//! Everywhere but Windows every start fails: no administrator level exists
//! there (§B.2.1).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use tornect_core::levels::{AdminPath, Availability, Elevation};
use tornect_input::InputSink;
use tornect_input::helper::{HelperLink, LinkEnd};
use tornect_platform::helper::NotGiven;
use tornect_session::MediaBackend;
use tornect_signal::fsm::host::{AdminHelper, AttachedHelper, KillSwitch};
use tornect_signal::fsm::{AuditEvent, HandshakeAudit, HelperEvent};
use tornect_signal::pairing::{BoxFuture, TrustedPeer};

/// The attached helpers of this host, by session.
pub struct AdminHelpers {
    links: Mutex<HashMap<String, HelperLink>>,
    wired: Mutex<Option<Wired>>,
    launcher: Option<Arc<dyn Launcher>>,
    /// The on-demand task of unattended administrator sessions.
    task: Option<Arc<dyn Launcher>>,
}

/// How a helper is started for one session: Windows' prompt on Windows (the
/// only launcher of a real host), a fake over a socket pair in tests.
pub trait Launcher: Send + Sync {
    /// Start a helper and wait until it is connected, checked and ready
    /// (blocking: Windows' prompt is answered inside).
    fn launch(&self) -> Result<Box<dyn Pending>, NotGiven>;
}

/// A helper connected, checked and ready, not attached yet; dropped, it
/// ends (its pipe closes, its process is ended).
pub trait Pending: Send {
    /// Attach it: the returned link is the session's injector from now on;
    /// `ended` hears how the helper ended the link.
    fn attach(self: Box<Self>, ended: Box<dyn FnOnce(LinkEnd) + Send>) -> HelperLink;
}

/// What the helpers learn when the host is wired.
#[derive(Clone)]
struct Wired {
    kill: KillSwitch,
    audit: Arc<dyn HandshakeAudit>,
    levels: Availability,
}

impl std::fmt::Debug for AdminHelpers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminHelpers").finish_non_exhaustive()
    }
}

impl AdminHelpers {
    /// This system's helpers: Windows' prompt on Windows, none elsewhere.
    /// [`Self::wire`] gives the host's kill path, log and row.
    #[must_use]
    pub fn new() -> Arc<Self> {
        #[cfg(windows)]
        {
            Self::with_task(
                Some(Arc::new(windows::Prompt)),
                Some(Arc::new(windows::Task)),
            )
        }
        #[cfg(not(windows))]
        {
            Self::with_task(None, None)
        }
    }

    /// Helpers started by `launcher` (`None`: never), and no task.
    #[cfg(all(test, unix))]
    #[must_use]
    pub fn with(launcher: Option<Arc<dyn Launcher>>) -> Arc<Self> {
        Self::with_task(launcher, None)
    }

    /// Helpers started by `launcher` for attended sessions and by `task` for
    /// unattended ones (`None`: never).
    #[must_use]
    pub fn with_task(
        launcher: Option<Arc<dyn Launcher>>,
        task: Option<Arc<dyn Launcher>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            links: Mutex::new(HashMap::new()),
            wired: Mutex::new(None),
            launcher,
            task,
        })
    }

    /// Start a helper with `launcher` for `peer`.
    async fn started(
        self: Arc<Self>,
        launcher: Option<Arc<dyn Launcher>>,
        peer: &TrustedPeer,
    ) -> Result<Box<dyn AttachedHelper>, &'static str> {
        let Some(launcher) = launcher else {
            return Err(NotGiven::Unavailable.reason());
        };
        // A start dropped before it resolves (the popup's time, or the
        // task's budget, ran out) drops the helper the blocking launch
        // returns: it ends, never attached.
        match tokio::task::spawn_blocking(move || launcher.launch()).await {
            Ok(Ok(pending)) => Ok(Box::new(Attached {
                helpers: self,
                device: peer.device,
                label: peer.label.clone(),
                pending,
            }) as Box<dyn AttachedHelper>),
            Ok(Err(not_given)) => Err(not_given.reason()),
            Err(_) => Err(NotGiven::NotStarted.reason()),
        }
    }

    /// The host's kill path (which a helper's panic or loss fires), its
    /// `sessions.log`, and its row of the §B.2.1 table.
    pub fn wire(&self, kill: KillSwitch, audit: Arc<dyn HandshakeAudit>, levels: Availability) {
        *self.wired.lock().unwrap_or_else(PoisonError::into_inner) = Some(Wired {
            kill,
            audit,
            levels,
        });
    }

    fn wired(&self) -> Option<Wired> {
        self.wired
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Whether this host's administrator answer takes no helper: every
    /// program here runs as administrator (UAC off), so does the host.
    fn full_token(&self) -> bool {
        self.wired().is_some_and(|w| {
            matches!(
                w.levels.answers.admin,
                Some(AdminPath::TornectConfirmation {
                    needs_helper: false
                })
            )
        })
    }

    /// The link of session `session_id`, taken for its injector.
    fn take(&self, session_id: &str) -> Option<HelperLink> {
        self.links
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(session_id)
    }

    /// Session `session_id` ended: a link its injector never took is
    /// stopped here (a link the injector took stops with it).
    pub fn end(&self, session_id: &str) {
        drop(self.take(session_id));
    }

    /// Keep `link` for session `session_id`.
    fn keep(&self, session_id: &str, link: HelperLink) {
        self.links
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(session_id.to_owned(), link);
    }
}

impl AdminHelper for AdminHelpers {
    fn start<'a>(
        self: Arc<Self>,
        peer: &'a TrustedPeer,
    ) -> BoxFuture<'a, Result<Box<dyn AttachedHelper>, &'static str>> {
        let launcher = self.launcher.clone();
        Box::pin(self.started(launcher, peer))
    }

    fn start_task<'a>(
        self: Arc<Self>,
        peer: &'a TrustedPeer,
    ) -> BoxFuture<'a, Result<Box<dyn AttachedHelper>, &'static str>> {
        let task = self.task.clone();
        Box::pin(self.started(task, peer))
    }
}

/// A helper connected and checked, waiting for the accept.
struct Attached {
    helpers: Arc<AdminHelpers>,
    device: tornect_core::DeviceId,
    label: String,
    pending: Box<dyn Pending>,
}

impl AttachedHelper for Attached {
    fn attach(self: Box<Self>, session_id: &str) {
        let Self {
            helpers,
            device,
            label,
            pending,
        } = *self;
        let (on_end, id) = (Arc::clone(&helpers), session_id.to_owned());
        let link = pending.attach(Box::new(move |end| {
            let Some(wired) = on_end.wired() else { return };
            wired.audit.record(AuditEvent::AdminHelper {
                device,
                label,
                session_id: Some(id),
                what: HelperEvent::Stopped,
                reason: end.reason(),
            });
            // The helper's panic chord, or its going away, ends the session
            // through the host's kill path.
            wired.kill.kill(match end {
                LinkEnd::Panic => tornect_signal::messages::bye::PANIC,
                LinkEnd::Stopped | LinkEnd::Lost => tornect_signal::messages::bye::ADMIN_END,
            });
        }));
        helpers.keep(session_id, link);
    }
}

/// The media backend of a host with the administrator helper: an
/// administrator session's input goes to its helper instead of the host's
/// own injector; every other session is the inner backend's. On the rows
/// where the host itself runs with a full token (UAC off), no helper is
/// needed and the inner injector serves.
pub struct AdminBackend {
    inner: Arc<dyn MediaBackend>,
    helpers: Arc<AdminHelpers>,
}

impl AdminBackend {
    /// `inner`, with `helpers` for the administrator sessions.
    #[must_use]
    pub fn new(inner: Arc<dyn MediaBackend>, helpers: Arc<AdminHelpers>) -> Self {
        Self { inner, helpers }
    }
}

impl MediaBackend for AdminBackend {
    fn open_source(
        &self,
        cancel: tokio::sync::watch::Receiver<bool>,
    ) -> Result<Box<dyn tornect_capture::VideoSource>, tornect_capture::CaptureError> {
        self.inner.open_source(cancel)
    }

    fn open_injector(&self) -> Option<Box<dyn InputSink>> {
        self.inner.open_injector()
    }

    fn open_session_injector(
        &self,
        session_id: &str,
        elevation: Elevation,
    ) -> Option<Box<dyn InputSink>> {
        if elevation != Elevation::Admin || self.helpers.full_token() {
            // Not an administrator session; or every program here runs as
            // administrator, and so does this host.
            return self.inner.open_injector();
        }
        // The helper, or no input at all: never the host's own injector for
        // a session signed at the administrator level.
        self.helpers
            .take(session_id)
            .map(|link| Box::new(link) as Box<dyn InputSink>)
    }

    fn view_only(&self) {
        self.inner.view_only();
    }

    fn session_ended(&self, session_id: &str) {
        self.helpers.end(session_id);
        self.inner.session_ended(session_id);
    }
}

#[cfg(windows)]
mod windows {
    //! The attended launch (NEEDS-DEVICE(windows)).

    use std::sync::{Arc, mpsc};
    use std::time::Instant;

    use tornect_input::helper::{FrameRead, FrameWrite, FromHelper, HARD_CAP, HelperLink, LinkEnd};

    /// Windows' prompt (`ShellExecuteExW`, verb `runas`).
    pub(super) struct Prompt;

    impl super::Launcher for Prompt {
        fn launch(&self) -> Result<Box<dyn super::Pending>, NotGiven> {
            launch_attended().map(|p| Box::new(p) as Box<dyn super::Pending>)
        }
    }

    /// The on-demand task `\Tornect admin helper <SID>` (unattended).
    pub(super) struct Task;

    impl super::Launcher for Task {
        fn launch(&self) -> Result<Box<dyn super::Pending>, NotGiven> {
            launch_task().map(|p| Box::new(p) as Box<dyn super::Pending>)
        }
    }

    /// Start the helper through the on-demand task (blocking): the ACL
    /// check before the run, then the client — the registered Program Files
    /// image, elevated, in this session — and its `Ready`, within the budget.
    fn launch_task() -> Result<Pending, NotGiven> {
        use tornect_platform::helper_task;

        let install = helper_task::this_install().map_err(|_| NotGiven::Unavailable)?;
        let tasks = helper_task::for_this_user().map_err(|_| NotGiven::Unavailable)?;
        let session = tornect_platform::helper::own_session().map_err(|_| NotGiven::Unavailable)?;
        let name = new_pipe_name().map_err(|_| NotGiven::NoPipe)?;
        // The task runs as this user: the pipe admits this user only.
        let pipe = Arc::new(create_pipe(&name, false).map_err(|_| NotGiven::NoPipe)?);
        let args = HelperArgs {
            pipe: name,
            host_pid: own_pid(),
            hard_cap: HARD_CAP,
        };
        helper_task::run(&tasks, &install, &args).map_err(|e| {
            tracing::warn!(error = %e, "starting the administrator helper task");
            NotGiven::NotStarted
        })?;
        let pending = Pending {
            pipe: Some(pipe),
            launched: None,
        };
        let expect = Expect::Task {
            image: install.exe,
            session,
        };
        ready(pending, &expect)
    }
    use tornect_platform::helper::{
        BUDGET, Expect, HelperArgs, HelperPipe, LaunchedHelper, NotGiven, accept_client,
        check_client, client_facts, create_pipe, is_administrator, launch_helper, new_pipe_name,
        own_image, own_pid,
    };

    /// A helper connected, checked and ready; ended on drop unless attached.
    pub(super) struct Pending {
        pipe: Option<Arc<HelperPipe>>,
        launched: Option<LaunchedHelper>,
    }

    impl Drop for Pending {
        fn drop(&mut self) {
            // Never attached: close its pipe; the launched handle's drop ends it.
            if let Some(pipe) = self.pipe.take() {
                pipe.close();
            }
        }
    }

    struct Writer(Arc<HelperPipe>);

    impl FrameWrite for Writer {
        fn write_frame(&self, frame: &[u8; 16]) -> std::io::Result<()> {
            self.0.write_frame(frame)
        }

        fn close(&self) {
            self.0.close();
        }
    }

    struct Reader(Arc<HelperPipe>);

    impl FrameRead for Reader {
        fn read_frame(&mut self) -> std::io::Result<Option<[u8; 16]>> {
            self.0.read_frame()
        }
    }

    impl super::Pending for Pending {
        /// The session's link: heartbeats, input, `Stop` at its end.
        fn attach(mut self: Box<Self>, ended: Box<dyn FnOnce(LinkEnd) + Send>) -> HelperLink {
            if let Some(launched) = self.launched.take() {
                launched.keep();
            }
            // The link owns the pipe now: nothing for this one to close.
            let pipe = self.pipe.take().expect("a pending helper has its pipe");
            HelperLink::attach(
                Arc::new(Writer(Arc::clone(&pipe))),
                Box::new(Reader(pipe)),
                ended,
            )
        }
    }

    impl Pending {
        fn pipe(&self) -> &HelperPipe {
            self.pipe.as_deref().expect("a pending helper has its pipe")
        }
    }

    /// Start the helper for one attended session (blocking: Windows' prompt
    /// is answered inside).
    pub(super) fn launch_attended() -> Result<Pending, NotGiven> {
        let name = new_pipe_name().map_err(|_| NotGiven::NoPipe)?;
        // On a standard account the helper runs as the administrator whose
        // password was typed: the pipe admits Administrators too.
        let administrators = !is_administrator().map_err(|_| NotGiven::Unavailable)?;
        let pipe = Arc::new(create_pipe(&name, administrators).map_err(|_| NotGiven::NoPipe)?);
        let exe = own_image().map_err(|_| NotGiven::Unavailable)?;
        // What Windows' prompt will run as administrator must be a file only
        // administrators can change (the rule of the helper task, H6, kept
        // for the attended path too).
        {
            use tornect_platform::helper_task;
            let install = helper_task::this_install().map_err(|_| NotGiven::Unavailable)?;
            let tasks = helper_task::for_this_user().map_err(|_| NotGiven::Unavailable)?;
            helper_task::check_files(&tasks, &install).map_err(|e| {
                tracing::warn!(error = %e, "the administrator helper's files");
                NotGiven::Refused
            })?;
        }
        let args = HelperArgs {
            pipe: name,
            host_pid: own_pid(),
            hard_cap: HARD_CAP,
        };
        // Blocks until Windows' prompt was answered and the helper started.
        let launched = launch_helper(std::path::Path::new(&exe), &args)?;
        let expect = Expect::Launched {
            pid: launched.pid(),
        };
        let pending = Pending {
            pipe: Some(pipe),
            launched: Some(launched),
        };
        ready(pending, &expect)
    }

    /// Wait, within [`BUDGET`] from now, for `pending`'s one client, check it
    /// against `expect`, and read its `Ready`; anything else ends it.
    fn ready(pending: Pending, expect: &Expect) -> Result<Pending, NotGiven> {
        let deadline = Instant::now() + BUDGET;
        if !accept_client(pending.pipe(), BUDGET).map_err(|_| NotGiven::Late)? {
            return Err(NotGiven::Late);
        }
        let facts = client_facts(pending.pipe()).map_err(|_| NotGiven::Refused)?;
        check_client(expect, &facts).map_err(|_| NotGiven::Refused)?;
        // Its `Ready`, within what is left of the budget.
        let (tx, rx) = mpsc::channel();
        let pipe = Arc::clone(pending.pipe.as_ref().ok_or(NotGiven::Late)?);
        std::thread::spawn(move || {
            let _ = tx.send(pipe.read_frame());
        });
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(Ok(Some(frame))) if FromHelper::decode(&frame) == Some(FromHelper::Ready) => {
                Ok(pending)
            }
            // Late (the pending read is cancelled when `pending` drops) or
            // anything else.
            _ => Err(NotGiven::Late),
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc;
    use std::time::Duration;

    use tornect_input::helper::{
        Event, Exit, FrameRead, FromHelper, Limits, LockedWriter, forward_frames, read_frame_from,
        run_helper,
    };
    use tornect_input::{InputError, InputEvent};

    use super::*;

    /// Records what reaches it: the helper's injector, or the host's own.
    #[derive(Clone, Default)]
    struct Recording(Arc<Mutex<Vec<InputEvent>>>);

    impl InputSink for Recording {
        fn inject(&mut self, event: &InputEvent) -> Result<(), InputError> {
            self.0.lock().unwrap().push(*event);
            Ok(())
        }
    }

    struct Socket(UnixStream);

    impl FrameRead for Socket {
        fn read_frame(&mut self) -> std::io::Result<Option<[u8; 16]>> {
            read_frame_from(&mut self.0)
        }
    }

    /// A launcher whose helper is a thread running the helper's own loop
    /// over a socket pair: the fake pipe of the Linux tests.
    #[derive(Default)]
    struct SocketLauncher {
        injected: Recording,
        exits: Arc<Mutex<Vec<Exit>>>,
        chord: Mutex<Option<mpsc::Sender<Event>>>,
    }

    struct SocketPending(UnixStream);

    impl Pending for SocketPending {
        fn attach(self: Box<Self>, ended: Box<dyn FnOnce(LinkEnd) + Send>) -> HelperLink {
            let close = self.0.try_clone().unwrap();
            HelperLink::attach(
                Arc::new(LockedWriter::new(self.0.try_clone().unwrap(), move |_| {
                    let _ = close.shutdown(std::net::Shutdown::Both);
                })),
                Box::new(Socket(self.0)),
                ended,
            )
        }
    }

    impl Launcher for SocketLauncher {
        fn launch(&self) -> Result<Box<dyn Pending>, NotGiven> {
            let (host, helper) = UnixStream::pair().unwrap();
            let (tx, events) = mpsc::channel();
            *self.chord.lock().unwrap() = Some(tx.clone());
            let (sink, exits) = (self.injected.clone(), Arc::clone(&self.exits));
            std::thread::spawn(move || {
                use std::io::Write as _;
                let mut out = helper.try_clone().unwrap();
                out.write_all(&FromHelper::Ready.encode()).unwrap();
                let mut read = Socket(helper);
                std::thread::spawn(move || forward_frames(&mut read, &tx));
                let exit = run_helper(sink, &events, Limits::default(), &mut || {
                    let _ = out.write_all(&FromHelper::Panic.encode());
                });
                exits.lock().unwrap().push(exit);
            });
            let mut read = host.try_clone().unwrap();
            let ready = read_frame_from(&mut read).unwrap().unwrap();
            assert_eq!(FromHelper::decode(&ready), Some(FromHelper::Ready));
            Ok(Box::new(SocketPending(host)))
        }
    }

    #[derive(Default)]
    struct Audit(Mutex<Vec<AuditEvent>>);

    impl HandshakeAudit for Audit {
        fn record(&self, event: AuditEvent) {
            self.0.lock().unwrap().push(event);
        }
    }

    /// The host's own injector, told apart from the helper's.
    struct Inner(Recording);

    impl MediaBackend for Inner {
        fn open_source(
            &self,
            _: tokio::sync::watch::Receiver<bool>,
        ) -> Result<Box<dyn tornect_capture::VideoSource>, tornect_capture::CaptureError> {
            Err(tornect_capture::CaptureError::Unavailable("test".into()))
        }

        fn open_injector(&self) -> Option<Box<dyn InputSink>> {
            Some(Box::new(self.0.clone()))
        }
    }

    fn peer() -> TrustedPeer {
        TrustedPeer {
            device: tornect_core::DeviceId::from_bytes([4; 32]),
            label: "Laptop".to_owned(),
        }
    }

    fn installed() -> Availability {
        Availability::of(Some(&tornect_core::levels::WindowsFacts {
            installed: true,
            administrator: true,
            ..tornect_core::levels::WindowsFacts::default()
        }))
    }

    struct Rig {
        launcher: Arc<SocketLauncher>,
        helpers: Arc<AdminHelpers>,
        backend: AdminBackend,
        own: Recording,
        kill: KillSwitch,
        audit: Arc<Audit>,
    }

    fn rig() -> Rig {
        let launcher = Arc::new(SocketLauncher::default());
        let helpers = AdminHelpers::with(Some(launcher.clone() as Arc<dyn Launcher>));
        let (kill, audit) = (KillSwitch::new(), Arc::new(Audit::default()));
        helpers.wire(kill.clone(), audit.clone(), installed());
        let own = Recording::default();
        let backend = AdminBackend::new(Arc::new(Inner(own.clone())), Arc::clone(&helpers));
        Rig {
            launcher,
            helpers,
            backend,
            own,
            kill,
            audit,
        }
    }

    async fn attached(rig: &Rig, session_id: &str) {
        let helper = Arc::clone(&rig.helpers).start(&peer()).await.unwrap();
        helper.attach(session_id);
    }

    fn wait_for(what: impl Fn() -> bool) {
        for _ in 0..400 {
            if what() {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("timed out");
    }

    /// The fake pipe end to end: an attached helper becomes the injector of
    /// its administrator session; its input goes to the helper, never to the
    /// host's own injector; the session's end stops the helper.
    #[tokio::test]
    async fn an_administrator_sessions_input_goes_to_its_helper() {
        let rig = rig();
        attached(&rig, "s1").await;
        let mut sink = rig
            .backend
            .open_session_injector("s1", Elevation::Admin)
            .expect("the helper is the injector");
        let press = InputEvent::Key {
            usb: 0x07_0004,
            pressed: true,
        };
        sink.inject(&press).unwrap();
        wait_for(|| rig.launcher.injected.0.lock().unwrap().contains(&press));
        assert!(rig.own.0.lock().unwrap().is_empty(), "never the host's own");
        drop(sink);
        wait_for(|| !rig.launcher.exits.lock().unwrap().is_empty());
        assert_eq!(*rig.launcher.exits.lock().unwrap(), vec![Exit::Stopped]);
        // The helper let go of the key it held before it exited.
        assert_eq!(
            rig.launcher.injected.0.lock().unwrap().last(),
            Some(&InputEvent::Key {
                usb: 0x07_0004,
                pressed: false,
            })
        );
        assert_eq!(rig.kill.fired(), None, "the host stopped it: no kill");
    }

    /// A session that ends before its injector took the helper stops the
    /// helper at its end (H3), and a session at none uses the host's own
    /// injector; an administrator session without a helper gets no input at
    /// all, never the host's own injector.
    #[tokio::test]
    async fn a_helper_never_outlives_its_session() {
        let rig = rig();
        attached(&rig, "s2").await;
        rig.backend.session_ended("s2");
        wait_for(|| !rig.launcher.exits.lock().unwrap().is_empty());
        assert_eq!(*rig.launcher.exits.lock().unwrap(), vec![Exit::Stopped]);
        assert!(
            rig.backend
                .open_session_injector("s2", Elevation::Admin)
                .is_none(),
            "gone with its session"
        );
        assert!(
            rig.backend
                .open_session_injector("other", Elevation::Admin)
                .is_none()
        );
        let mut own = rig
            .backend
            .open_session_injector("plain", Elevation::None)
            .unwrap();
        own.inject(&InputEvent::PointerMove { x: 1, y: 2 }).unwrap();
        assert_eq!(rig.own.0.lock().unwrap().len(), 1);
    }

    /// The helper's panic chord: the helper lets go and exits, and the host's
    /// kill path ends the session; `sessions.log` hears the helper stopped.
    #[tokio::test]
    async fn the_helpers_panic_chord_fires_the_kill_path() {
        let rig = rig();
        attached(&rig, "s3").await;
        let mut sink = rig
            .backend
            .open_session_injector("s3", Elevation::Admin)
            .unwrap();
        let chord = rig.launcher.chord.lock().unwrap().clone().unwrap();
        chord.send(Event::PanicChord).unwrap();
        wait_for(|| rig.kill.fired().is_some());
        assert_eq!(rig.kill.fired(), Some(tornect_signal::messages::bye::PANIC));
        assert_eq!(*rig.launcher.exits.lock().unwrap(), vec![Exit::Panic]);
        assert!(
            sink.inject(&InputEvent::PointerMove { x: 3, y: 3 })
                .is_err()
        );
        let stopped = rig.audit.0.lock().unwrap().iter().any(|e| {
            matches!(e, AuditEvent::AdminHelper { what: HelperEvent::Stopped, session_id: Some(id), .. } if id == "s3")
        });
        assert!(stopped);
    }

    /// Without a launcher (every system but Windows) no helper starts.
    #[tokio::test]
    async fn no_launcher_no_helper() {
        let helpers = AdminHelpers::with(None);
        let err = helpers.start(&peer()).await.err().unwrap();
        assert_eq!(err, NotGiven::Unavailable.reason());
    }
}
