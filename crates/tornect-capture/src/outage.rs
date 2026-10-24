//! A polling source's grabs through a spell in which the screen cannot be
//! read.
//!
//! On Windows a user-session process cannot read the secure desktop: while a
//! UAC prompt, the Ctrl+Alt+Del screen or the lock screen is the input
//! desktop, `GetDC` or `BitBlt` fails (`docs/PLAN.md` §B.8.8). That must not
//! end the session: in a control session the host's secure-screen watch
//! tells the viewer why the picture stands still, and the picture comes back
//! once the prompt is answered. So a failed grab is waited out. The source says it has no new
//! picture, as a damage-driven source does when the screen is still, after
//! waiting what the caller allowed: answering at once would make the capture
//! thread, which asks again straight away, spin. Only a spell that lasts
//! [`OUTAGE_LIMIT`] ends capture, with the grab's own error.

use std::time::{Duration, Instant};

use crate::{CaptureError, Frame};

/// How long the screen may stay unreadable before capture ends: long enough
/// for the person at the host to answer a UAC prompt, short enough that a
/// locked host (which no user-session process can read until it is unlocked)
/// does not keep a frozen session for long.
pub(crate) const OUTAGE_LIMIT: Duration = Duration::from_secs(60);

/// When the grabs began to fail, if they fail now.
#[derive(Debug)]
pub(crate) struct Outage {
    limit: Duration,
    since: Option<Instant>,
}

impl Default for Outage {
    fn default() -> Self {
        Self::new(OUTAGE_LIMIT)
    }
}

impl Outage {
    /// Grabs that may fail for up to `limit` in a row.
    pub(crate) fn new(limit: Duration) -> Self {
        Self { limit, since: None }
    }

    /// One poll of the screen with `grab`. A picture ends any spell. A
    /// failure waits `timeout` and answers `Ok(None)`, until the failures
    /// have lasted `limit` without a picture between them; that one is
    /// returned.
    pub(crate) fn poll(
        &mut self,
        timeout: Duration,
        grab: impl FnOnce() -> Result<Frame, CaptureError>,
    ) -> Result<Option<Frame>, CaptureError> {
        match grab() {
            Ok(frame) => {
                if let Some(since) = self.since.take() {
                    tracing::info!(
                        after_ms = since.elapsed().as_millis() as u64,
                        "the screen can be read again: the picture goes on"
                    );
                }
                Ok(Some(frame))
            }
            Err(e) => {
                let now = Instant::now();
                let since = *self.since.get_or_insert_with(|| {
                    tracing::warn!(
                        error = %e,
                        "the screen cannot be read (a secure Windows screen, such as a UAC \
                         prompt or the lock screen?): the picture waits"
                    );
                    now
                });
                if now.saturating_duration_since(since) >= self.limit {
                    tracing::warn!(
                        error = %e,
                        limit_s = self.limit.as_secs(),
                        "the screen stayed unreadable: capture ends"
                    );
                    return Err(e);
                }
                std::thread::sleep(timeout);
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn picture() -> Frame {
        Frame {
            width: 2,
            height: 2,
            bgrx: vec![0xff; 16],
            captured_at: Instant::now(),
            grab: Duration::ZERO,
        }
    }

    fn failed() -> Result<Frame, CaptureError> {
        Err(CaptureError::Failed(
            "BitBlt failed: Access is denied.".to_owned(),
        ))
    }

    const WAIT: Duration = Duration::from_millis(20);

    /// A failed grab is no new picture, after the caller's wait, and the
    /// next picture comes through as before.
    #[test]
    fn a_failed_grab_waits_and_says_no_new_picture() {
        let mut outage = Outage::new(Duration::from_secs(60));
        assert!(outage.poll(WAIT, || Ok(picture())).unwrap().is_some());
        for _ in 0..3 {
            let started = Instant::now();
            assert!(outage.poll(WAIT, failed).unwrap().is_none());
            assert!(
                started.elapsed() >= WAIT,
                "answered at once: the thread would spin"
            );
        }
        let frame = outage.poll(WAIT, || Ok(picture())).unwrap();
        assert_eq!(frame.map(|f| (f.width, f.height)), Some((2, 2)));
    }

    /// Only a spell that lasts the limit ends capture, with the grab's own
    /// error; a picture in between starts the count again.
    #[test]
    fn only_a_spell_that_lasts_the_limit_ends_capture() {
        let limit = Duration::from_millis(500);
        let mut outage = Outage::new(limit);
        let first = Instant::now();
        assert!(outage.poll(WAIT, failed).unwrap().is_none());
        while first.elapsed() < limit / 2 {
            assert!(outage.poll(WAIT, failed).unwrap().is_none());
        }
        // A picture: the spell is over, and the next one counts from its own
        // first failure (had it not, it would end after half the limit).
        assert!(outage.poll(WAIT, || Ok(picture())).unwrap().is_some());
        let second = Instant::now();
        let ended = loop {
            match outage.poll(WAIT, failed) {
                Ok(None) => assert!(second.elapsed() < Duration::from_secs(10), "never ended"),
                Ok(Some(_)) => panic!("a picture from a failed grab"),
                Err(e) => break e,
            }
        };
        assert!(
            second.elapsed() >= limit,
            "ended after {:?}",
            second.elapsed()
        );
        assert!(
            matches!(&ended, CaptureError::Failed(why) if why.starts_with("BitBlt failed")),
            "{ended}"
        );
    }

    /// The default rides out a minute, the time a person has to answer a
    /// UAC prompt before the session ends.
    #[test]
    fn the_default_limit_is_a_minute() {
        assert_eq!(Outage::default().limit, Duration::from_secs(60));
        assert_eq!(OUTAGE_LIMIT, Duration::from_secs(60));
    }
}
