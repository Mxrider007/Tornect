//! Test doubles that more than one module's tests use.

use tornect_platform::autostart::{self, Autostart, AutostartState};

/// A start-at-login backend that records what it was asked and answers
/// as scripted.
#[derive(Default)]
pub(crate) struct FakeAutostart {
    pub(crate) installs: std::sync::Mutex<Vec<bool>>,
    pub(crate) uninstalls: std::sync::atomic::AtomicUsize,
    pub(crate) state: std::sync::Mutex<Option<AutostartState>>,
    /// `Some`: `preflight` refuses with this reason.
    pub(crate) refuse: Option<String>,
    /// `Some`: `install`/`uninstall` fail with this reason after preflight.
    pub(crate) fail: Option<String>,
    /// `Some`: `status` fails with this reason.
    pub(crate) unreadable_status: Option<String>,
}

impl FakeAutostart {
    pub(crate) fn installs(&self) -> Vec<bool> {
        self.installs.lock().unwrap().clone()
    }

    pub(crate) fn uninstalls(&self) -> usize {
        self.uninstalls.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Autostart for FakeAutostart {
    fn preflight(&self, _elevated: bool) -> Result<(), autostart::AutostartError> {
        match &self.refuse {
            Some(why) => Err(autostart::AutostartError::Unavailable(why.clone())),
            None => Ok(()),
        }
    }

    fn install(&self, elevated: bool) -> Result<AutostartState, autostart::AutostartError> {
        self.preflight(elevated)?;
        self.installs.lock().unwrap().push(elevated);
        if let Some(why) = &self.fail {
            return Err(autostart::AutostartError::Failed(why.clone()));
        }
        let state = AutostartState::Registered(autostart::Registration {
            enabled: true,
            elevated,
            command: Some("\"/opt/tornect\" \"host\"".to_owned()),
            note: None,
            unreadable: false,
        });
        *self.state.lock().unwrap() = Some(state.clone());
        Ok(state)
    }

    fn uninstall(&self) -> Result<AutostartState, autostart::AutostartError> {
        self.uninstalls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if let Some(why) = &self.fail {
            return Err(autostart::AutostartError::Failed(why.clone()));
        }
        *self.state.lock().unwrap() = None;
        Ok(AutostartState::Absent)
    }

    fn status(&self) -> Result<AutostartState, autostart::AutostartError> {
        if let Some(why) = &self.unreadable_status {
            return Err(autostart::AutostartError::Failed(why.clone()));
        }
        Ok(self
            .state
            .lock()
            .unwrap()
            .clone()
            .unwrap_or(AutostartState::Absent))
    }

    fn describe(&self) -> String {
        "the test's start-at-login backend".to_owned()
    }

    fn manual_removal(&self) -> String {
        "remove it by hand as the test says".to_owned()
    }
}

/// Re-authentication that answers each dialog in turn as scripted (`true`:
/// confirmed, `false`: refused, as when the person cancels it), confirming
/// once the script is used up, and records every dialog by its operation.
pub(crate) struct ReAuthSequence {
    answers: std::sync::Mutex<std::collections::VecDeque<bool>>,
    calls: std::sync::Mutex<Vec<String>>,
}

impl ReAuthSequence {
    pub(crate) fn new(answers: &[bool]) -> Self {
        Self {
            answers: std::sync::Mutex::new(answers.iter().copied().collect()),
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

impl tornect_core::unattended::guard::ReAuth for ReAuthSequence {
    fn reauthenticate(&self, op: &str) -> Result<(), tornect_core::unattended::guard::ReAuthError> {
        self.calls.lock().unwrap().push(op.to_owned());
        match self.answers.lock().unwrap().pop_front() {
            Some(false) => Err(tornect_core::unattended::guard::ReAuthError::Denied),
            _ => Ok(()),
        }
    }
}

/// A close reason as a hostile host would write it: a terminal escape that
/// clears the screen, words of its own, a bell.
pub(crate) const HOSTILE_REASON: &[u8] = b"\x1b[2J\x1b[Hpwned: type your password\x07";

/// No text of `texts` holds [`HOSTILE_REASON`]'s words or any control
/// character but the line breaks of an error's `Debug` (anyhow's own
/// layout of the chain, as the terminal prints a returned error).
pub(crate) fn none_holds_the_reason(texts: &[String]) {
    for text in texts {
        assert!(!text.contains("pwned"), "{text:?}");
        assert!(
            !text.chars().any(|c| c.is_control() && c != '\n'),
            "{text:?}"
        );
    }
}

/// The error a direct media bind fails with when the host, its key pinned
/// and proven, reads the viewer's `Bind` and then closes the connection
/// with `reason`, as a host of another build may (design `direct` §5.5):
/// two machines on one in-memory LAN, the links started as a session
/// starts them.
pub(crate) async fn bind_closed_with_reason(reason: &'static [u8]) -> tornect_session::ViewerError {
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::io::AsyncReadExt as _;
    use tornect_core::DeviceIdentity;
    use tornect_net::mem::{LinkSpec, MachineSpec, MemNet};
    use tornect_net::{DirectLink, DirectParams, LocalBatch, NetEnv, Scope, TornectRole};
    use tornect_session::{Binding, MediaViewer};
    use tornect_signal::consent::SessionToken;

    const WAIT: Duration = Duration::from_secs(10);
    let net = MemNet::new(7);
    let lan = net.segment(LinkSpec::LAN);
    let viewer_env: Arc<dyn NetEnv> =
        Arc::new(net.machine(MachineSpec::on(lan, "192.168.1.10/24")));
    let host_env: Arc<dyn NetEnv> = Arc::new(net.machine(MachineSpec::on(lan, "192.168.1.20/24")));
    let token = SessionToken::new([0x42; 32]);
    let device = |seed: u8| Arc::new(DeviceIdentity::from_seed(&[seed; 32]));
    let params = |me, mine: u8, peer: u8| DirectParams {
        me,
        identity: device(mine),
        peer_pk: device(peer).verifying_key().to_bytes(),
        session_token: zeroize::Zeroizing::new(*token.bytes()),
        direct_port: None,
        scope: Scope::SameSite,
        gather: tornect_net::GatherConfig::default(),
    };
    let (mut viewer, viewer_offered) =
        DirectLink::start(params(TornectRole::Viewer, 0x22, 0x44), viewer_env)
            .await
            .expect("the viewer's link");
    let (mut host, host_offered) =
        DirectLink::start(params(TornectRole::Host, 0x44, 0x22), host_env)
            .await
            .expect("the host's link");
    host.add_remote(viewer_offered, Scope::SameSite);
    assert_eq!(viewer.next_local().await, LocalBatch::Done);
    host.remote_done();
    viewer.add_remote(host_offered, Scope::SameSite);
    assert_eq!(host.next_local().await, LocalBatch::Done);
    viewer.remote_done();
    let (v, h) = tokio::time::timeout(WAIT, async {
        tokio::join!(viewer.established(), host.established())
    })
    .await
    .expect("in time");
    let (v, h) = (v.expect("the viewer's connection"), h.expect("the host's"));
    let hostile = tokio::spawn(async move {
        let mut stream = h.accept_stream().await.expect("the media stream");
        let mut first = [0; 1];
        stream.read_exact(&mut first).await.expect("the Bind");
        h.close_with_reason(0x0abc, reason);
        stream
    });
    let stream = v.open_stream(1).await.expect("the media stream");
    let failed = MediaViewer::bind(stream, &Binding::new(&token, &[0; 32]), WAIT)
        .await
        .expect_err("the host closed the connection");
    drop(hostile.await);
    viewer.close().await;
    host.close().await;
    failed
}
