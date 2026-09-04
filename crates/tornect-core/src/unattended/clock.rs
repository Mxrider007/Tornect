//! The [`Clock`] trait of `docs/PLAN.md` §B.8.5.3: a wall-clock reading (unix seconds)
//! and an `Instant`-like monotonic reading, consumed by the attempt limiter, the decay
//! twins and the schedule / `active_from` / `expires_at` checks.
//!
//! Production uses [`SystemClock`] (`SystemTime` + a process-start `Instant`; the
//! monotonic reading does not advance across a suspend on Linux/macOS, accepted as
//! conservative per §B.8.5.1). Tests and the fuzz loaders use [`FakeClock`], which
//! steps each reading independently.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;

/// Wall + monotonic clock (§B.8.5.3).
pub trait Clock: Send + Sync {
    /// Unix seconds (the only wall-clock reading; forgeable, so used only for stamping
    /// and for the load-time decay of §B.8.5.1).
    fn wall(&self) -> u64;
    /// Monotonic reading since an arbitrary origin (never goes backwards; runtime locks
    /// and runtime decay live on this reading).
    fn mono(&self) -> Duration;
}

/// The OS clocks.
#[derive(Debug, Clone)]
pub struct SystemClock {
    start: Instant,
}

impl SystemClock {
    /// A clock whose monotonic origin is now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn wall(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn mono(&self) -> Duration {
        self.start.elapsed()
    }
}

/// A scripted clock for tests and fuzzing: the wall and the monotonic reading are
/// stepped independently, so a forward jump, a rollback or a suspend (wall advanced,
/// monotonic untouched) can be reproduced exactly (§B.8.15 U5).
#[derive(Debug)]
pub struct FakeClock {
    inner: Mutex<(u64, Duration)>,
}

impl FakeClock {
    /// A clock reading `wall` seconds and `mono` on the monotonic axis.
    #[must_use]
    pub fn new(wall: u64, mono: Duration) -> Self {
        Self {
            inner: Mutex::new((wall, mono)),
        }
    }

    /// A clock at unix `wall` with a zero monotonic origin.
    #[must_use]
    pub fn at(wall: u64) -> Self {
        Self::new(wall, Duration::ZERO)
    }

    /// Advance both readings by `d` (normal passage of time).
    pub fn advance(&self, d: Duration) {
        let mut g = self.inner.lock();
        g.0 = g.0.saturating_add(d.as_secs());
        g.1 = g.1.saturating_add(d);
    }

    /// Advance only the wall clock (an NTP step forward, or a suspend the monotonic
    /// clock does not see).
    pub fn advance_wall(&self, secs: u64) {
        let mut g = self.inner.lock();
        g.0 = g.0.saturating_add(secs);
    }

    /// Advance only the monotonic reading.
    pub fn advance_mono(&self, d: Duration) {
        let mut g = self.inner.lock();
        g.1 = g.1.saturating_add(d);
    }

    /// Set the wall clock (a rollback when `wall` is earlier than the current reading).
    pub fn set_wall(&self, wall: u64) {
        self.inner.lock().0 = wall;
    }
}

impl Clock for FakeClock {
    fn wall(&self) -> u64 {
        self.inner.lock().0
    }

    fn mono(&self) -> Duration {
        self.inner.lock().1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_clock_steps_axes_independently() {
        let c = FakeClock::at(1000);
        assert_eq!(c.wall(), 1000);
        assert_eq!(c.mono(), Duration::ZERO);
        c.advance(Duration::from_secs(5));
        assert_eq!((c.wall(), c.mono()), (1005, Duration::from_secs(5)));
        c.advance_wall(100);
        assert_eq!((c.wall(), c.mono()), (1105, Duration::from_secs(5)));
        c.advance_mono(Duration::from_secs(1));
        assert_eq!((c.wall(), c.mono()), (1105, Duration::from_secs(6)));
        c.set_wall(50);
        assert_eq!(c.wall(), 50);
    }

    #[test]
    fn system_clock_is_monotone_and_roughly_now() {
        let c = SystemClock::new();
        let a = c.mono();
        let b = c.mono();
        assert!(b >= a);
        assert!(c.wall() > 1_700_000_000);
    }
}
