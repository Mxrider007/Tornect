//! The releases of router mappings that run on their own (design `direct`
//! §7.4 "Release"): a mapping dropped without [`Mapping::release`] has its
//! release spawned here, capped at [`MAP_RELEASE_CAP`] and counted, so that
//! the app's shutdown can wait a moment for them
//! ([`ReleaseTracker::wait`] with [`SHUTDOWN_RELEASE_WAIT`]) and the kill
//! and panic paths never wait at all.
//!
//! [`Mapping::release`]: super::Mapping::release

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use tokio::runtime::Handle;
use tokio::sync::watch;

use crate::BoxFuture;

/// The longest one release runs once spawned; past it the router's lease
/// ends the mapping (design §7.4).
pub const MAP_RELEASE_CAP: Duration = Duration::from_secs(1);

/// How long the app's shutdown waits for the releases still running
/// (`RealNet::releases().wait(SHUTDOWN_RELEASE_WAIT)`, design §8.5).
pub const SHUTDOWN_RELEASE_WAIT: Duration = Duration::from_secs(1);

/// Counts the releases running. Clones share the count.
#[derive(Clone)]
pub struct ReleaseTracker {
    running: Arc<watch::Sender<usize>>,
}

impl Default for ReleaseTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ReleaseTracker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReleaseTracker")
            .field("running", &self.running())
            .finish()
    }
}

/// One running release: counted from its spawn until its task ends, is
/// cancelled, or is dropped unrun by a runtime that shut down.
struct Running(Arc<watch::Sender<usize>>);

impl Running {
    fn new(running: &Arc<watch::Sender<usize>>) -> Self {
        running.send_modify(|n| *n += 1);
        Self(Arc::clone(running))
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.0.send_modify(|n| *n = n.saturating_sub(1));
    }
}

impl ReleaseTracker {
    /// A tracker with nothing running.
    #[must_use]
    pub fn new() -> Self {
        Self {
            running: Arc::new(watch::Sender::new(0)),
        }
    }

    /// Runs `release` on `rt`, capped at [`MAP_RELEASE_CAP`] and counted
    /// until it ends. `rt` need not be the current runtime: a mapping
    /// dropped outside any runtime context releases on the one it was made
    /// on.
    pub fn spawn(&self, rt: &Handle, release: BoxFuture<'static, ()>) {
        let running = Running::new(&self.running);
        drop(rt.spawn(async move {
            let _running = running;
            let _ = tokio::time::timeout(MAP_RELEASE_CAP, release).await;
        }));
    }

    /// How many releases run now.
    #[must_use]
    pub fn running(&self) -> usize {
        *self.running.borrow()
    }

    /// Waits until no release runs, at most `max`; whether none does.
    pub async fn wait(&self, max: Duration) -> bool {
        let mut rx = self.running.subscribe();
        tokio::time::timeout(max, rx.wait_for(|n| *n == 0))
            .await
            .is_ok_and(|r| r.is_ok())
    }
}
