//! Bounds on what one peer can make the other buffer, send or inject
//! (SLICE-A2 A2-3, A2-6), the gate on the viewer's quality changes, and the
//! host's per-stage means. Pure state, driven with explicit instants.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use tornect_proto::HostStats;

/// The host's send window: access units sent and not yet acknowledged, at most
/// `max_frames` of them and fewer than `max_bytes` bytes.
///
/// An empty window always takes one more access unit, whatever its size, so a
/// keyframe larger than `max_bytes` cannot stall the stream.
#[derive(Debug)]
pub struct AckWindow {
    max_frames: usize,
    max_bytes: usize,
    /// Each unit's sequence number, length and when it was written.
    in_flight: VecDeque<(u32, usize, Instant)>,
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

    /// Resize the window to `max_frames` (at least one) units and `max_bytes`
    /// bytes. Nothing in flight is dropped: a window made smaller than what
    /// is in flight admits nothing until acks drain it below the new size.
    pub fn set_limits(&mut self, max_frames: usize, max_bytes: usize) {
        self.max_frames = max_frames.max(1);
        self.max_bytes = max_bytes;
    }

    /// Whether another access unit may be sent.
    #[must_use]
    pub fn has_room(&self) -> bool {
        self.in_flight.is_empty()
            || (self.in_flight.len() < self.max_frames && self.bytes < self.max_bytes)
    }

    /// Access unit `seq`, `len` bytes, went out at `now`.
    pub fn sent(&mut self, seq: u32, len: usize, now: Instant) {
        self.in_flight.push_back((seq, len, now));
        self.bytes = self.bytes.saturating_add(len);
    }

    /// Access unit `seq` was fully written at `now`: its round trip is
    /// counted from then. A unit is put in flight when its write starts
    /// ([`Self::sent`]), since acks are taken while the write waits; the
    /// viewer can acknowledge it only once it has all of it, so the stamp
    /// moves before its ack comes. A unit not in flight changes nothing.
    pub fn written(&mut self, seq: u32, now: Instant) {
        if let Some(unit) = self.in_flight.iter_mut().rev().find(|(s, ..)| *s == seq) {
            unit.2 = now;
        }
    }

    /// The viewer acknowledged `seq` at `now`: the round trip of that unit,
    /// from its write to `now`. The stream is ordered, so everything sent
    /// before `seq` is acknowledged with it. An ack for a unit not in flight
    /// changes nothing and returns `None`: acks only ever shrink the window.
    pub fn ack(&mut self, seq: u32, now: Instant) -> Option<Duration> {
        let pos = self.in_flight.iter().position(|&(s, ..)| s == seq)?;
        let mut sent_at = now;
        for (_, len, at) in self.in_flight.drain(..=pos) {
            self.bytes = self.bytes.saturating_sub(len);
            sent_at = at;
        }
        Some(now.saturating_duration_since(sent_at))
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

    /// From when [`Self::allow`] admits a keyframe: `None` before any was
    /// forced (it admits one now), otherwise an instant that may already be
    /// past.
    #[must_use]
    pub fn ready_at(&self) -> Option<Instant> {
        self.last.map(|last| later(last, self.interval))
    }
}

/// `at + by`, or the latest instant this platform can hold after `at`.
fn later(at: Instant, by: Duration) -> Instant {
    let mut by = by;
    loop {
        if let Some(t) = at.checked_add(by) {
            return t;
        }
        by /= 2;
    }
}

/// The host's gate on the viewer's quality changes (the quality design §5.3,
/// §6.6): a `SetQuality` costs a store (the latest one wins), and the host
/// acts on one at most once per `interval`, the first at once. What it does
/// (a new encoder, or a `Quality` for the preset already in use) is the
/// caller's; an encoder rebuild also spends the keyframe limiter's turn.
#[derive(Debug)]
pub struct QualityGate {
    interval: Duration,
    wanted: Option<u8>,
    last: Option<Instant>,
}

impl QualityGate {
    /// At most one action per `interval`.
    #[must_use]
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            wanted: None,
            last: None,
        }
    }

    /// The viewer asked for preset `code`; it replaces any request not acted
    /// on yet.
    pub fn request(&mut self, code: u8) {
        self.wanted = Some(code);
    }

    /// The request not acted on yet.
    #[must_use]
    pub fn wanted(&self) -> Option<u8> {
        self.wanted
    }

    /// From when [`Self::take`] acts: `None` before its first action (the
    /// first request acts at once), otherwise an instant that may already be
    /// past.
    #[must_use]
    pub fn ready_at(&self) -> Option<Instant> {
        self.last.map(|last| later(last, self.interval))
    }

    /// The request to act on at `now`, if there is one and the interval since
    /// the last action has passed; it is cleared and `now` is the last
    /// action.
    pub fn take(&mut self, now: Instant) -> Option<u8> {
        if self.ready_at().is_some_and(|at| now < at) {
            return None;
        }
        let code = self.wanted.take()?;
        self.last = Some(now);
        Some(code)
    }
}

/// What each stage took for one encoded picture.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StageTimes {
    /// The source's own cost to produce the picture (`Frame.grab`).
    pub grab: Duration,
    /// From its capture to its encode starting.
    pub age: Duration,
    /// Fitting it under its cap.
    pub scale: Duration,
    /// BGRx → I420.
    pub convert: Duration,
    /// OpenH264's encode.
    pub encode: Duration,
}

/// Per-stage means over a window of about `every`, for the host's `Stats`
/// (the quality design §4.3). A repeat of the last picture (a quality
/// change on a still screen) counts its scale, convert and encode, never a
/// grab or an age: nothing new was captured.
#[derive(Debug)]
pub struct StatsWindow {
    every: Duration,
    start: Instant,
    frames: u64,
    fresh: u64,
    grab_us: u64,
    age_us: u64,
    scale_us: u64,
    convert_us: u64,
    encode_us: u64,
    sends: u64,
    send_us: u64,
    acks: u64,
    ack_us: u64,
}

impl StatsWindow {
    /// A window of `every`, opening at `now`.
    #[must_use]
    pub fn new(every: Duration, now: Instant) -> Self {
        Self {
            every,
            start: now,
            frames: 0,
            fresh: 0,
            grab_us: 0,
            age_us: 0,
            scale_us: 0,
            convert_us: 0,
            encode_us: 0,
            sends: 0,
            send_us: 0,
            acks: 0,
            ack_us: 0,
        }
    }

    /// A picture went out; `fresh` unless it repeats the last one.
    pub fn frame(&mut self, times: &StageTimes, fresh: bool) {
        self.frames = self.frames.saturating_add(1);
        add(&mut self.scale_us, times.scale);
        add(&mut self.convert_us, times.convert);
        add(&mut self.encode_us, times.encode);
        if fresh {
            self.fresh = self.fresh.saturating_add(1);
            add(&mut self.grab_us, times.grab);
            add(&mut self.age_us, times.age);
        }
    }

    /// A picture took `took` from encoded to fully written.
    pub fn sent(&mut self, took: Duration) {
        self.sends = self.sends.saturating_add(1);
        add(&mut self.send_us, took);
    }

    /// An acknowledged picture's round trip, from written to its `VideoAck`.
    pub fn acked(&mut self, rtt: Duration) {
        self.acks = self.acks.saturating_add(1);
        add(&mut self.ack_us, rtt);
    }

    /// Whether the window has lasted `every` at `now`.
    #[must_use]
    pub fn due(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.start) >= self.every
    }

    /// The window's means at `now`, with the captured size `source`; a new
    /// window opens at `now`. Every mean saturates, and a mean over nothing
    /// is 0.
    pub fn take(&mut self, now: Instant, source: (u32, u32)) -> HostStats {
        let window_ms = now.saturating_duration_since(self.start).as_millis();
        let short = |v: u64| u16::try_from(v).unwrap_or(u16::MAX);
        let edge = |v: u32| u16::try_from(v).unwrap_or(u16::MAX);
        let stats = HostStats {
            source_width: edge(source.0),
            source_height: edge(source.1),
            frames: short(self.frames),
            window_ms: u16::try_from(window_ms).unwrap_or(u16::MAX).max(1),
            grab_us: mean(self.grab_us, self.fresh),
            age_us: mean(self.age_us, self.fresh),
            scale_us: mean(self.scale_us, self.frames),
            convert_us: mean(self.convert_us, self.frames),
            encode_us: mean(self.encode_us, self.frames),
            send_us: mean(self.send_us, self.sends),
            ack_us: mean(self.ack_us, self.acks),
        };
        *self = Self::new(self.every, now);
        stats
    }
}

/// At most `max` log lines in each `window`, for lines a peer that has not
/// bound a session can cause: such a peer must not be able to fill the log
/// file. Each line let through says how many were left out before it.
#[derive(Debug)]
pub struct LineBudget {
    window: Duration,
    max: u32,
    started: Option<Instant>,
    used: u32,
    left_out: u64,
}

impl LineBudget {
    /// A budget of `max` lines in each `window`.
    #[must_use]
    pub fn new(window: Duration, max: u32) -> Self {
        Self {
            window,
            max,
            started: None,
            used: 0,
            left_out: 0,
        }
    }

    /// Whether a line may be logged at `now`: `Some` with the number of
    /// lines left out since the last one let through, or `None` (counted)
    /// once this window's lines are used up. A window starts with the first
    /// line asked for after the last one ended; a clock that went backwards
    /// stays in the current window.
    pub fn take(&mut self, now: Instant) -> Option<u64> {
        if self
            .started
            .is_none_or(|s| now.saturating_duration_since(s) >= self.window)
        {
            self.started = Some(now);
            self.used = 0;
        }
        if self.used < self.max {
            self.used += 1;
            Some(std::mem::take(&mut self.left_out))
        } else {
            self.left_out = self.left_out.saturating_add(1);
            None
        }
    }
}

/// Add `d` in microseconds to `sum`, saturating.
fn add(sum: &mut u64, d: Duration) {
    *sum = sum.saturating_add(u64::try_from(d.as_micros()).unwrap_or(u64::MAX));
}

/// `sum / n`, saturating to `u32`; 0 over nothing.
fn mean(sum: u64, n: u64) -> u32 {
    sum.checked_div(n)
        .map_or(0, |m| u32::try_from(m).unwrap_or(u32::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_window_counts_frames_and_bytes() {
        let t0 = Instant::now();
        let mut w = AckWindow::new(3, 1000);
        assert!(w.has_room());
        w.sent(1, 100, t0);
        w.sent(2, 100, t0);
        w.sent(3, 100, t0);
        assert!(!w.has_room(), "three frames fill a three-frame window");
        assert!(w.ack(1, t0).is_some());
        assert!(w.has_room());
        assert_eq!((w.frames(), w.bytes()), (2, 200));

        let mut w = AckWindow::new(8, 1000);
        w.sent(7, 600, t0);
        w.sent(8, 500, t0);
        assert!(!w.has_room(), "1100 bytes are over a 1000-byte window");
    }

    #[test]
    fn an_ack_covers_everything_before_it_and_a_bogus_ack_changes_nothing() {
        let t0 = Instant::now();
        let mut w = AckWindow::new(8, 1 << 20);
        for seq in [u32::MAX - 1, u32::MAX, 0, 1] {
            w.sent(seq, 10, t0);
        }
        assert!(w.ack(5, t0).is_none(), "never sent");
        assert_eq!(w.frames(), 4);
        assert!(
            w.ack(0, t0).is_some(),
            "a wrapped sequence number is found by value"
        );
        assert_eq!((w.frames(), w.bytes()), (1, 10));
        assert!(w.ack(0, t0).is_none(), "already acknowledged");
        assert!(w.ack(1, t0).is_some());
        assert_eq!((w.frames(), w.bytes()), (0, 0));
    }

    #[test]
    fn an_oversized_keyframe_still_goes_out_into_an_empty_window() {
        let t0 = Instant::now();
        let mut w = AckWindow::new(8, 1000);
        assert!(w.has_room());
        w.sent(1, 5000, t0);
        assert!(!w.has_room());
        assert!(w.ack(1, t0).is_some());
        assert!(w.has_room());
    }

    /// An ack gives the round trip of the unit it names, from its write;
    /// the units it covers before it are let go of with it; a clock that
    /// went backwards gives zero.
    #[test]
    fn an_ack_gives_the_round_trip_of_the_unit_it_names() {
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        let mut w = AckWindow::new(8, 1 << 20);
        w.sent(1, 10, t0);
        w.sent(2, 10, t0 + ms(100));
        w.sent(3, 10, t0 + ms(200));
        assert_eq!(w.ack(2, t0 + ms(1300)), Some(ms(1200)), "unit 2's own");
        assert_eq!(w.frames(), 1);
        assert_eq!(w.ack(3, t0 + ms(100)), Some(Duration::ZERO));
        assert_eq!(w.ack(3, t0 + ms(900)), None, "already acknowledged");

        // Counted from the end of the write once it is stamped.
        w.sent(4, 10, t0);
        w.written(4, t0 + ms(400));
        w.written(99, t0 + ms(400));
        assert_eq!(w.frames(), 1, "an unknown unit changes nothing");
        assert_eq!(w.ack(4, t0 + ms(1500)), Some(ms(1100)));
    }

    /// A smaller window admits nothing until acks drain it below its new
    /// size; nothing in flight is dropped; a larger one admits at once.
    #[test]
    fn a_resized_window_drains_before_it_admits() {
        let t0 = Instant::now();
        let mut w = AckWindow::new(30, 1 << 20);
        for seq in 0..10 {
            w.sent(seq, 1000, t0);
        }
        assert!(w.has_room());
        w.set_limits(4, 1 << 20);
        assert!(!w.has_room());
        assert_eq!((w.frames(), w.bytes()), (10, 10_000), "nothing dropped");
        w.ack(5, t0);
        assert!(!w.has_room(), "four left in a four-unit window");
        w.ack(6, t0);
        assert!(w.has_room());
        w.set_limits(30, 2500);
        assert!(!w.has_room(), "3000 bytes are over 2500");
        w.set_limits(0, 1 << 20);
        assert!(!w.has_room(), "at least one unit, and three are in flight");
        w.ack(9, t0);
        assert!(w.has_room(), "an empty window always takes one");
        w.set_limits(30, 1 << 20);
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

    /// `ready_at` says when `allow` next admits one: now before any was
    /// forced, an interval after the last otherwise; a refused request does
    /// not move it; an interval too long for the clock gives a far instant,
    /// never a panic.
    #[test]
    fn the_keyframe_limiter_says_when_it_is_ready() {
        let t0 = Instant::now();
        let s = Duration::from_secs(1);
        let mut k = KeyframeLimiter::new(s);
        assert_eq!(k.ready_at(), None);
        assert!(k.allow(t0));
        assert_eq!(k.ready_at(), Some(t0 + s));
        assert!(!k.allow(t0 + s / 2));
        assert_eq!(k.ready_at(), Some(t0 + s), "a refusal moves nothing");
        let at = k.ready_at().unwrap();
        assert!(!k.allow(at - Duration::from_nanos(1)));
        assert!(k.allow(at));

        let mut k = KeyframeLimiter::new(Duration::MAX);
        assert!(k.allow(t0));
        let far = k.ready_at().unwrap();
        assert!(far > t0 + Duration::from_secs(1 << 30));
        assert!(!k.allow(far - Duration::from_secs(1)));
    }

    /// The gate acts on the first request at once, on the latest of several,
    /// and at most once per interval; with nothing wanted it does nothing
    /// and its clock stays.
    #[test]
    fn the_quality_gate_acts_at_once_then_once_per_interval() {
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        let mut g = QualityGate::new(ms(2000));
        assert_eq!((g.wanted(), g.ready_at()), (None, None));
        assert_eq!(g.take(t0), None, "nothing wanted");
        assert_eq!(g.ready_at(), None, "doing nothing is no action");

        g.request(3);
        assert_eq!(g.ready_at(), None, "the first request acts at once");
        assert_eq!(g.take(t0), Some(3));
        assert_eq!(g.wanted(), None);
        assert_eq!(g.ready_at(), Some(t0 + ms(2000)));

        // Latest wins, and nothing acts before the interval is over.
        for code in [1, 2, 1, 3, 2] {
            g.request(code);
        }
        assert_eq!(g.wanted(), Some(2));
        assert_eq!(g.take(t0 + ms(1999)), None);
        assert_eq!(g.wanted(), Some(2), "kept for its turn");
        assert_eq!(g.take(t0 + ms(2000)), Some(2));
        assert_eq!(g.ready_at(), Some(t0 + ms(4000)));

        // A flood over 10 s acts at most once per interval: 5 times.
        let mut acted = 0;
        for i in 0..2000u64 {
            let now = t0 + ms(4000) + ms(5 * i);
            g.request(u8::try_from(i % 3).unwrap() + 1);
            acted += u32::from(g.take(now).is_some());
        }
        assert_eq!(acted, 5);
    }

    fn times(ms: u64) -> StageTimes {
        let d = Duration::from_millis(ms);
        StageTimes {
            grab: d,
            age: d * 2,
            scale: d * 3,
            convert: d * 4,
            encode: d * 5,
        }
    }

    /// Means over the window, in microseconds; a repeat adds its scale,
    /// convert and encode but no grab or age; sends and acks have their own
    /// counts; `take` opens a new, empty window.
    #[test]
    fn the_stats_window_means_each_stage() {
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        let mut w = StatsWindow::new(ms(1000), t0);
        assert!(!w.due(t0 + ms(999)));
        assert!(w.due(t0 + ms(1000)));
        w.frame(&times(1), true);
        w.frame(&times(3), true);
        w.frame(&times(8), false);
        w.sent(ms(100));
        w.sent(ms(300));
        w.acked(ms(1100));
        let stats = w.take(t0 + ms(1234), (2560, 1440));
        assert_eq!(
            stats,
            HostStats {
                source_width: 2560,
                source_height: 1440,
                frames: 3,
                window_ms: 1234,
                grab_us: 2000,
                age_us: 4000,
                scale_us: 12_000,
                convert_us: 16_000,
                encode_us: 20_000,
                send_us: 200_000,
                ack_us: 1_100_000,
            }
        );
        // A new window: nothing yet, and its means are zero.
        assert!(!w.due(t0 + ms(1234)));
        let empty = w.take(t0 + ms(1234), (640, 360));
        assert_eq!(
            empty,
            HostStats {
                source_width: 640,
                source_height: 360,
                window_ms: 1,
                ..HostStats::default()
            },
            "a zero-length window still says 1 ms"
        );
        // Only repeats: no grab or age.
        w.frame(&times(4), false);
        let repeats = w.take(t0 + ms(2000), (640, 360));
        assert_eq!((repeats.frames, repeats.grab_us, repeats.age_us), (1, 0, 0));
        assert_eq!(repeats.encode_us, 20_000);
        let wire = tornect_proto::Msg::Stats(stats);
        assert_eq!(
            tornect_proto::Msg::decode(&wire.encode()[4..]).unwrap(),
            wire
        );
    }

    /// Every field saturates: sizes and counts at `u16::MAX`, means at
    /// `u32::MAX`, the window's length at `u16::MAX` ms; a clock that went
    /// backwards gives a 1 ms window.
    #[test]
    fn the_stats_window_saturates() {
        let t0 = Instant::now();
        let mut w = StatsWindow::new(Duration::from_secs(1), t0);
        for _ in 0..70_000 {
            w.frame(&StageTimes::default(), true);
        }
        let huge = StageTimes {
            grab: Duration::MAX,
            age: Duration::MAX,
            scale: Duration::MAX,
            convert: Duration::MAX,
            encode: Duration::MAX,
        };
        w.frame(&huge, true);
        w.sent(Duration::MAX);
        w.acked(Duration::from_secs(5000));
        let stats = w.take(t0 + Duration::from_secs(100), (100_000, u32::MAX));
        assert_eq!(
            (stats.source_width, stats.source_height, stats.frames),
            (u16::MAX, u16::MAX, u16::MAX)
        );
        assert_eq!(stats.window_ms, u16::MAX);
        assert_eq!(
            (stats.grab_us, stats.encode_us, stats.send_us, stats.ack_us),
            (u32::MAX, u32::MAX, u32::MAX, u32::MAX)
        );
        let mut w = StatsWindow::new(Duration::from_secs(1), t0 + Duration::from_secs(5));
        assert!(!w.due(t0));
        assert_eq!(w.take(t0, (1, 1)).window_ms, 1);
    }

    /// The PR-C review's I-2: lines a peer without a session causes are
    /// let through `max` per window, the first one after a gap saying how
    /// many it left out; a new window starts with the first line after the
    /// last one ended, and a clock that went backwards stays in the window.
    #[test]
    fn a_line_budget_lets_max_lines_through_per_window_and_counts_the_rest() {
        let t0 = Instant::now();
        let s = Duration::from_secs;
        let mut b = LineBudget::new(s(60), 3);
        assert_eq!(b.take(t0), Some(0));
        assert_eq!(b.take(t0 + s(1)), Some(0));
        assert_eq!(b.take(t0 + s(2)), Some(0));
        for i in 0..1000 {
            assert_eq!(b.take(t0 + s(3) + Duration::from_millis(i)), None);
        }
        assert_eq!(b.take(t0 + s(59)), None, "still the first window");
        assert_eq!(b.take(t0), None, "a clock gone backwards: same window");
        assert_eq!(b.take(t0 + s(60)), Some(1002), "the next window says so");
        assert_eq!(b.take(t0 + s(61)), Some(0));
        assert_eq!(b.take(t0 + s(62)), Some(0));
        assert_eq!(b.take(t0 + s(63)), None);
        assert_eq!(b.take(t0 + s(500)), Some(1), "a quiet gap: a new window");

        let mut none = LineBudget::new(s(60), 0);
        assert_eq!(none.take(t0), None);
        assert_eq!(none.take(t0 + s(60)), None);
        let mut full = LineBudget::new(s(60), 0);
        full.left_out = u64::MAX;
        assert_eq!(full.take(t0), None);
        assert_eq!(full.left_out, u64::MAX, "saturates");
    }
}
