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
