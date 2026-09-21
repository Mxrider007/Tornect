//! Bounds on what one peer can make the other buffer, send or inject
//! (SLICE-A2 A2-3, A2-6). Pure state, driven with explicit instants.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// The host's send window: access units sent and not yet acknowledged, at most
/// `max_frames` of them and fewer than `max_bytes` bytes.
///
/// An empty window always takes one more access unit, whatever its size, so a
/// keyframe larger than `max_bytes` cannot stall the stream.
#[derive(Debug)]
pub struct AckWindow {
    max_frames: usize,
    max_bytes: usize,
    in_flight: VecDeque<(u32, usize)>,
    bytes: usize,
}

impl AckWindow {
    /// A window of `max_frames` (at least one) access units and `max_bytes` bytes.
    #[must_use]
    pub fn new(max_frames: usize, max_bytes: usize) -> Self {
        Self {
            max_frames: max_frames.max(1),
            max_bytes,
            in_flight: VecDeque::new(),
            bytes: 0,
        }
    }

    /// Whether another access unit may be sent.
    #[must_use]
    pub fn has_room(&self) -> bool {
        self.in_flight.is_empty()
            || (self.in_flight.len() < self.max_frames && self.bytes < self.max_bytes)
    }

    /// Access unit `seq`, `len` bytes, went out.
    pub fn sent(&mut self, seq: u32, len: usize) {
        self.in_flight.push_back((seq, len));
        self.bytes = self.bytes.saturating_add(len);
    }

    /// The viewer acknowledged `seq`. The stream is ordered, so everything sent
    /// before `seq` is acknowledged with it. An ack for a unit not in flight
    /// changes nothing and returns `false`: acks only ever shrink the window.
    pub fn ack(&mut self, seq: u32) -> bool {
        let Some(pos) = self.in_flight.iter().position(|&(s, _)| s == seq) else {
            return false;
        };
        for (_, len) in self.in_flight.drain(..=pos) {
            self.bytes = self.bytes.saturating_sub(len);
        }
        true
    }

    /// Access units in flight.
    #[must_use]
    pub fn frames(&self) -> usize {
        self.in_flight.len()
    }

    /// Bytes in flight.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

/// A token bucket: `rate` events a second on average, `burst` at once.
#[derive(Debug)]
pub struct TokenBucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    /// A full bucket at `now`.
    #[must_use]
    pub fn new(rate: u32, burst: u32, now: Instant) -> Self {
        let burst = f64::from(burst.max(1));
        Self {
            rate: f64::from(rate),
            burst,
            tokens: burst,
            last: now,
        }
    }

    /// Take a token at `now`; `false` when none is left.
    pub fn take(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = self.last.max(now);
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// At most one forced keyframe per `interval`. An IDR is many times the size of
/// a P-frame, so a peer asking for one after every access unit would multiply
/// the bitrate.
#[derive(Debug)]
pub struct KeyframeLimiter {
    interval: Duration,
    last: Option<Instant>,
}

impl KeyframeLimiter {
    /// One keyframe per `interval`.
    #[must_use]
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            last: None,
        }
    }

    /// Whether a request at `now` may force a keyframe.
    pub fn allow(&mut self, now: Instant) -> bool {
        match self.last {
            Some(last) if now.saturating_duration_since(last) < self.interval => false,
            _ => {
                self.last = Some(now);
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_window_counts_frames_and_bytes() {
        let mut w = AckWindow::new(3, 1000);
        assert!(w.has_room());
        w.sent(1, 100);
        w.sent(2, 100);
        w.sent(3, 100);
        assert!(!w.has_room(), "three frames fill a three-frame window");
        assert!(w.ack(1));
        assert!(w.has_room());
        assert_eq!((w.frames(), w.bytes()), (2, 200));

        let mut w = AckWindow::new(8, 1000);
        w.sent(7, 600);
        w.sent(8, 500);
        assert!(!w.has_room(), "1100 bytes are over a 1000-byte window");
    }

    #[test]
    fn an_ack_covers_everything_before_it_and_a_bogus_ack_changes_nothing() {
        let mut w = AckWindow::new(8, 1 << 20);
        for seq in [u32::MAX - 1, u32::MAX, 0, 1] {
            w.sent(seq, 10);
        }
        assert!(!w.ack(5), "never sent");
        assert_eq!(w.frames(), 4);
        assert!(w.ack(0), "a wrapped sequence number is found by value");
        assert_eq!((w.frames(), w.bytes()), (1, 10));
        assert!(!w.ack(0), "already acknowledged");
        assert!(w.ack(1));
        assert_eq!((w.frames(), w.bytes()), (0, 0));
    }

    #[test]
    fn an_oversized_keyframe_still_goes_out_into_an_empty_window() {
        let mut w = AckWindow::new(8, 1000);
        assert!(w.has_room());
        w.sent(1, 5000);
        assert!(!w.has_room());
        assert!(w.ack(1));
        assert!(w.has_room());
    }

    #[test]
    fn the_bucket_allows_a_burst_then_the_rate() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(10, 5, t0);
        assert_eq!((0..20).filter(|_| b.take(t0)).count(), 5, "the burst");
        assert!(!b.take(t0 + Duration::from_millis(50)), "half a token");
        assert!(
            b.take(t0 + Duration::from_millis(100)),
            "one token after 100 ms"
        );
        // Refill never exceeds the burst.
        let later = t0 + Duration::from_secs(3600);
        assert_eq!((0..20).filter(|_| b.take(later)).count(), 5);
        // A clock that goes backwards refills nothing.
        assert!(!b.take(t0));
    }

    #[test]
    fn keyframes_are_forced_at_most_once_per_interval() {
        let t0 = Instant::now();
        let mut k = KeyframeLimiter::new(Duration::from_secs(1));
        assert!(k.allow(t0));
        assert!(!k.allow(t0 + Duration::from_millis(999)));
        assert!(k.allow(t0 + Duration::from_secs(1)));
    }
}
