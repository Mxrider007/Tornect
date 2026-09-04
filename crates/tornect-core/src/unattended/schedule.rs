//! Weekly schedule evaluation (`docs/PLAN.md` §B.8.7.1 ⑤): windows wrap past midnight,
//! a DST gap is inside the window if either side is, an overlap resolves to the first
//! occurrence, and a time-zone snapshot that differs from the host's zone is surfaced
//! as a warning.
//!
//! No tzdb is compiled in at M1 (decision M1-15): the evaluator is generic over
//! [`LocalTz`], production passes a [`FixedOffset`] snapshot (name + offset) built by
//! the host from its OS clock, tests drive DST cases through [`TableTz`]; a
//! tzdb-backed `LocalTz` from `tornect-platform` is M6 work.

use super::grant::{UnattendedGrant, Window};

/// A local time zone: the UTC offset in force at a given instant.
pub trait LocalTz: Send + Sync {
    /// Zone name compared against `Window.tz` (IANA name or `UTC±HH:MM`).
    fn name(&self) -> &str;
    /// Offset from UTC, in minutes, in force at unix time `unix`.
    fn offset_minutes_at(&self, unix: u64) -> i32;
}

/// A zone with one fixed offset — the M1 production snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedOffset {
    name: String,
    offset_minutes: i32,
}

impl FixedOffset {
    /// A named zone at `offset_minutes` from UTC.
    #[must_use]
    pub fn new(name: impl Into<String>, offset_minutes: i32) -> Self {
        Self {
            name: name.into(),
            offset_minutes: offset_minutes.clamp(-14 * 60, 14 * 60),
        }
    }

    /// UTC.
    #[must_use]
    pub fn utc() -> Self {
        Self::new("UTC", 0)
    }

    /// The canonical `UTC±HH:MM` name for an offset (`UTC` for zero).
    #[must_use]
    pub fn name_for(offset_minutes: i32) -> String {
        if offset_minutes == 0 {
            return "UTC".to_owned();
        }
        let sign = if offset_minutes < 0 { '-' } else { '+' };
        let m = offset_minutes.unsigned_abs();
        format!("UTC{sign}{:02}:{:02}", m / 60, m % 60)
    }

    /// A snapshot named by its offset (`UTC+01:00`).
    #[must_use]
    pub fn from_offset(offset_minutes: i32) -> Self {
        Self::new(Self::name_for(offset_minutes), offset_minutes)
    }

    /// Parse a `UTC`, `UTC+HH:MM` or `UTC-HH:MM` name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        let rest = name.strip_prefix("UTC")?;
        if rest.is_empty() {
            return Some(Self::utc());
        }
        let (sign, hm) = match rest.as_bytes().first()? {
            b'+' => (1, &rest[1..]),
            b'-' => (-1, &rest[1..]),
            _ => return None,
        };
        let (h, m) = hm.split_once(':')?;
        let h: i32 = h.parse().ok()?;
        let m: i32 = m.parse().ok()?;
        if h > 14 || m > 59 {
            return None;
        }
        Some(Self::new(name, sign * (h * 60 + m)))
    }

    /// The offset in minutes.
    #[must_use]
    pub fn offset_minutes(&self) -> i32 {
        self.offset_minutes
    }
}

impl LocalTz for FixedOffset {
    fn name(&self) -> &str {
        &self.name
    }

    fn offset_minutes_at(&self, _: u64) -> i32 {
        self.offset_minutes
    }
}

/// A zone defined by an explicit transition table — test and fuzz support for the
/// DST rules (no tzdb at M1, decision M1-15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableTz {
    name: String,
    initial: i32,
    /// `(at, offset)`: from unix time `at` on, the offset is `offset`.
    transitions: Vec<(u64, i32)>,
}

impl TableTz {
    /// A zone starting at `initial` minutes with the given sorted transitions.
    #[must_use]
    pub fn new(name: impl Into<String>, initial: i32, mut transitions: Vec<(u64, i32)>) -> Self {
        transitions.sort_by_key(|t| t.0);
        Self {
            name: name.into(),
            initial,
            transitions,
        }
    }
}

impl LocalTz for TableTz {
    fn name(&self) -> &str {
        &self.name
    }

    fn offset_minutes_at(&self, unix: u64) -> i32 {
        let mut off = self.initial;
        for (at, o) in &self.transitions {
            if unix >= *at {
                off = *o;
            } else {
                break;
            }
        }
        off
    }
}

const DAY: i64 = 86_400;

/// Wall readings beyond this (≈ year 36 800) are clamped at the public entry points:
/// every internal `i64` step (offset ≤ 14 h, ± 2 days, 8-day look-ahead) then stays
/// far from overflow, so a fuzzed `Clock` (F3) cannot drive the arithmetic to a panic.
const MAX_NOW: u64 = 1 << 40;

fn clamp_now(now: u64) -> i64 {
    i64::try_from(now.min(MAX_NOW)).unwrap_or(i64::MAX)
}

/// A local wall time mapped to an instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Resolved {
    /// Exactly one instant has this wall time.
    Unique(i64),
    /// Two instants do (fall-back overlap): the first occurrence.
    First(i64),
    /// None does (spring-forward gap): the transition instant.
    Gap(i64),
}

impl Resolved {
    fn instant(self) -> i64 {
        match self {
            Self::Unique(t) | Self::First(t) | Self::Gap(t) => t,
        }
    }
}

fn offset_at(tz: &dyn LocalTz, unix: i64) -> i64 {
    i64::from(tz.offset_minutes_at(u64::try_from(unix).unwrap_or(0))) * 60
}

/// Map local wall seconds to an instant under `tz` (§B.8.7.1 ⑤ gap/overlap rules).
fn resolve(tz: &dyn LocalTz, local: i64) -> Resolved {
    let before = offset_at(tz, local.saturating_sub(DAY));
    let after = offset_at(tz, local.saturating_add(DAY));
    let mut valid: Vec<i64> = Vec::with_capacity(2);
    for o in [before, after] {
        let t = local.saturating_sub(o);
        if offset_at(tz, t) == o && !valid.contains(&t) {
            valid.push(t);
        }
    }
    match valid.len() {
        1 => Resolved::Unique(valid[0]),
        2 => Resolved::First(valid[0].min(valid[1])),
        _ => {
            // Gap: binary-search the transition instant inside [local - DAY, local + DAY].
            let (mut lo, mut hi) = (local.saturating_sub(DAY), local.saturating_add(DAY));
            while hi.saturating_sub(lo) > 1 {
                let mid = lo + hi.saturating_sub(lo) / 2;
                if offset_at(tz, mid) == before {
                    lo = mid;
                } else {
                    hi = mid;
                }
            }
            Resolved::Gap(hi)
        }
    }
}

/// Day of week of a local timestamp, Monday = 0 … Sunday = 6.
fn weekday(local: i64) -> u8 {
    // 1970-01-01 was a Thursday (3 in Monday-based numbering).
    let days = local.div_euclid(DAY);
    u8::try_from((days + 3).rem_euclid(7)).unwrap_or(0)
}

fn day_start(local: i64) -> i64 {
    local.div_euclid(DAY) * DAY
}

fn span_end_min(w: &Window) -> i64 {
    let (s, e) = (i64::from(w.start_min), i64::from(w.end_min));
    if e <= s { e + 1440 } else { e }
}

/// The `[start, end)` instants of the occurrence of `w` anchored on the local day
/// containing `anchor_local`, if that day is one of the window's days.
fn occurrence(tz: &dyn LocalTz, w: &Window, anchor_local: i64) -> Option<(i64, i64)> {
    let d = weekday(anchor_local);
    if w.days & (1 << d) == 0 {
        return None;
    }
    let ds = day_start(anchor_local);
    let start = resolve(tz, ds.saturating_add(i64::from(w.start_min) * 60)).instant();
    let end = resolve(tz, ds.saturating_add(span_end_min(w) * 60)).instant();
    (end > start).then_some((start, end))
}

fn local_now(tz: &dyn LocalTz, now: i64) -> i64 {
    now.saturating_add(offset_at(tz, now))
}

/// Whether any window is open at `now`.
#[must_use]
pub fn is_open(windows: &[Window], now: u64, tz: &dyn LocalTz) -> bool {
    let now = clamp_now(now);
    let ln = local_now(tz, now);
    windows.iter().any(|w| {
        (-2..=1).any(|k| {
            occurrence(tz, w, ln.saturating_add(k * DAY)).is_some_and(|(s, e)| s <= now && now < e)
        })
    })
}

/// The instant the current open period ends (contiguous windows merged), if open.
#[must_use]
pub fn current_end(windows: &[Window], now: u64, tz: &dyn LocalTz) -> Option<u64> {
    let now_i = clamp_now(now);
    let mut end: Option<i64> = None;
    let mut probe = now_i;
    for _ in 0..64 {
        let ln = local_now(tz, probe);
        let best = windows
            .iter()
            .flat_map(|w| {
                (-2..=1).filter_map(move |k| occurrence(tz, w, ln.saturating_add(k * DAY)))
            })
            .filter(|(s, e)| *s <= probe && probe < *e)
            .map(|(_, e)| e)
            .max();
        match best {
            Some(e) if end.is_none_or(|cur| e > cur) => {
                end = Some(e);
                probe = e;
            }
            _ => break,
        }
    }
    end.and_then(|e| u64::try_from(e).ok())
}

/// The next instant a window opens at or after `from` (looking 8 days ahead).
#[must_use]
pub fn next_open_at(windows: &[Window], from: u64, tz: &dyn LocalTz) -> Option<u64> {
    let from_i = clamp_now(from);
    if is_open(windows, from, tz) {
        return Some(from);
    }
    let ln = local_now(tz, from_i);
    windows
        .iter()
        .flat_map(|w| (-1..=8).filter_map(move |k| occurrence(tz, w, ln.saturating_add(k * DAY))))
        .filter(|(s, _)| *s > from_i)
        .map(|(s, _)| s)
        .min()
        .and_then(|s| u64::try_from(s).ok())
}

/// Seconds until the grant next becomes usable — `active_from` first, then the
/// schedule — or `None` when it is usable now or never opens within 8 days
/// (`NOT_YET_ACTIVE` / `OUTSIDE_SCHEDULE.next_open_in_s`, §B.8.4.6).
#[must_use]
pub fn next_open_in_s(grant: &UnattendedGrant, now: u64, tz: &dyn LocalTz) -> Option<u32> {
    let from = now.max(grant.active_from);
    let at = match &grant.schedule {
        None => from,
        Some(ws) => next_open_at(ws, from, tz)?,
    };
    if at <= now {
        return None;
    }
    Some(u32::try_from(at - now).unwrap_or(u32::MAX))
}

/// Whether the grant's schedule is closed at `now` (`None` schedule = always open).
#[must_use]
pub fn outside_schedule(grant: &UnattendedGrant, now: u64, tz: &dyn LocalTz) -> bool {
    match &grant.schedule {
        None => false,
        Some(ws) => !is_open(ws, now, tz),
    }
}

/// The zone names of windows defined in another zone than the host's current one
/// (surfaced as the §B.8.7.1 ⑤ "time zone changed" warning).
#[must_use]
pub fn tz_mismatches(windows: &[Window], tz: &dyn LocalTz) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for w in windows {
        if w.tz != tz.name() && !out.contains(&w.tz) {
            out.push(w.tz.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // 2024-03-04 is a Monday; 2024-03-04T00:00:00Z = 1709510400.
    const MON_0: u64 = 1_709_510_400;
    const H: u64 = 3600;

    fn w(days: u8, start: u16, end: u16, tz: &str) -> Window {
        Window {
            days,
            start_min: start,
            end_min: end,
            tz: tz.into(),
        }
    }

    #[test]
    fn weekday_numbering_is_monday_based() {
        assert_eq!(weekday(i64::try_from(MON_0).unwrap()), 0);
        assert_eq!(weekday(i64::try_from(MON_0).unwrap() + 6 * 86_400), 6);
        assert_eq!(weekday(0), 3, "1970-01-01 was a Thursday");
    }

    #[test]
    fn u2_window_wraps_past_midnight() {
        let utc = FixedOffset::utc();
        let ws = [w(0b0000001, 22 * 60, 2 * 60, "UTC")]; // Monday 22:00 – Tuesday 02:00
        assert!(!is_open(&ws, MON_0 + 21 * H, &utc));
        assert!(is_open(&ws, MON_0 + 22 * H, &utc));
        assert!(is_open(&ws, MON_0 + 25 * H, &utc), "Tuesday 01:00");
        assert!(
            !is_open(&ws, MON_0 + 26 * H, &utc),
            "Tuesday 02:00 is the end"
        );
        assert!(
            !is_open(&ws, MON_0 + 7 * 24 * H + 25 * H - 7 * 24 * H + 24 * H, &utc),
            "Wednesday 01:00"
        );
        assert_eq!(current_end(&ws, MON_0 + 23 * H, &utc), Some(MON_0 + 26 * H));
        assert_eq!(
            next_open_at(&ws, MON_0 + 27 * H, &utc),
            Some(MON_0 + 7 * 24 * H + 22 * H)
        );
        // a full-day window (end == start)
        let all = [w(0b0000010, 0, 0, "UTC")];
        assert!(is_open(&all, MON_0 + 24 * H + 12 * H, &utc));
        assert!(!is_open(&all, MON_0 + 12 * H, &utc));
    }

    #[test]
    fn u2_offset_is_applied_in_local_time() {
        let plus2 = FixedOffset::from_offset(120);
        assert_eq!(plus2.name(), "UTC+02:00");
        let ws = [w(0b0000001, 9 * 60, 17 * 60, "UTC+02:00")]; // Monday 09:00–17:00 local = 07:00–15:00Z
        assert!(!is_open(&ws, MON_0 + 6 * H, &plus2));
        assert!(is_open(&ws, MON_0 + 7 * H, &plus2));
        assert!(!is_open(&ws, MON_0 + 15 * H, &plus2));
        assert_eq!(
            FixedOffset::parse("UTC-05:30").unwrap().offset_minutes(),
            -330
        );
        assert!(FixedOffset::parse("Europe/Lisbon").is_none());
    }

    /// Spring forward on Monday at 02:00 local (+1 → +2): 01:59:59 is followed by 03:00.
    fn spring_forward() -> TableTz {
        let transition = MON_0 + H; // 01:00Z = 02:00 local at +1
        TableTz::new("Test/Spring", 60, vec![(transition, 120)])
    }

    #[test]
    fn u2_dst_gap_boundary_is_inside_if_either_side_is() {
        let tz = spring_forward();
        let transition = MON_0 + H;
        // window 02:30–04:00 starts inside the gap ⇒ starts at the transition instant
        let ws = [w(0b0000001, 150, 240, "Test/Spring")];
        assert!(
            is_open(&ws, transition, &tz),
            "03:00 local, right after the gap"
        );
        assert!(is_open(&ws, transition + 10 * 60, &tz), "03:10 local");
        assert!(
            !is_open(&ws, transition - 1, &tz),
            "01:59:59 local, before the gap"
        );
        assert!(
            !is_open(&ws, transition + 60 * 60, &tz),
            "04:00 local = end"
        );
        // window 01:00–02:30 ends inside the gap ⇒ ends at the transition instant
        let ws = [w(0b0000001, 60, 150, "Test/Spring")];
        assert!(is_open(&ws, transition - 30 * 60, &tz), "01:30 local");
        assert!(
            !is_open(&ws, transition + 60, &tz),
            "03:01 local: the gap closed it"
        );
        assert_eq!(
            current_end(&ws, transition - 30 * 60, &tz),
            Some(transition)
        );
        // a window spanning the whole gap simply loses the hour
        let ws = [w(0b0000001, 60, 300, "Test/Spring")];
        assert_eq!(
            current_end(&ws, transition - 30 * 60, &tz),
            Some(transition + 2 * H)
        );
    }

    /// Fall back on Monday at 03:00 local (+2 → +1): 02:59:59 is followed by 02:00 again.
    fn fall_back() -> TableTz {
        let transition = MON_0 + H; // 01:00Z = 03:00 local at +2 = 02:00 local at +1
        TableTz::new("Test/Fall", 120, vec![(transition, 60)])
    }

    #[test]
    fn u2_dst_overlap_resolves_to_the_first_occurrence() {
        let tz = fall_back();
        let transition = MON_0 + H;
        // 02:30 local happens twice: first at transition - 30 min, again at transition + 30 min
        let ws = [w(0b0000001, 150, 300, "Test/Fall")]; // 02:30–05:00
        assert!(is_open(&ws, transition - 15 * 60, &tz), "first 02:45");
        assert!(
            is_open(&ws, transition + 45 * 60, &tz),
            "second 02:45 (inside the span)"
        );
        assert!(!is_open(&ws, transition - 45 * 60, &tz), "first 02:15");
        // 00:00–02:30: the end is ambiguous ⇒ first occurrence ⇒ closed during the repeated hour
        let ws = [w(0b0000001, 0, 150, "Test/Fall")];
        assert!(is_open(&ws, transition - 45 * 60, &tz), "first 02:15");
        assert!(
            !is_open(&ws, transition + 15 * 60, &tz),
            "second 02:15: already ended"
        );
        assert_eq!(
            current_end(&ws, transition - 45 * 60, &tz),
            Some(transition - 30 * 60)
        );
    }

    #[test]
    fn u2_tz_change_is_surfaced() {
        let host = FixedOffset::from_offset(60);
        let ws = [
            w(1, 0, 60, "UTC+02:00"),
            w(1, 0, 60, "UTC+01:00"),
            w(1, 0, 60, "UTC+02:00"),
        ];
        assert_eq!(tz_mismatches(&ws, &host), vec!["UTC+02:00".to_owned()]);
        assert!(tz_mismatches(&ws[1..2], &host).is_empty());
    }

    #[test]
    fn u2_next_open_in_s_honours_active_from_and_schedule() {
        use crate::id::DeviceId;
        use crate::session_log::Actor;
        use crate::unattended::grant::{AuthRecord, Preset, UnattendedGrant};
        use zeroize::Zeroizing;
        let utc = FixedOffset::utc();
        let mut g = UnattendedGrant::from_preset(
            [1; 8],
            DeviceId::from_bytes([2; 32]),
            "x",
            Actor::Ui,
            Preset::HelpingSomeone,
            1,
            AuthRecord::Opaque {
                record: Zeroizing::new(vec![0; 192]),
            },
            MON_0,
        )
        .unwrap();
        // cooling-off: 12 h
        assert_eq!(next_open_in_s(&g, MON_0 + 3600, &utc), Some(11 * 3600));
        assert_eq!(next_open_in_s(&g, MON_0 + 12 * 3600, &utc), None);
        // schedule Tuesday 09:00–10:00: from Monday 13:00 the next opening is Tue 09:00
        g.schedule = Some(vec![w(0b0000010, 9 * 60, 10 * 60, "UTC")]);
        assert_eq!(next_open_in_s(&g, MON_0 + 13 * H, &utc), Some(20 * 3600));
        assert_eq!(next_open_in_s(&g, MON_0 + 24 * H + 9 * H + 60, &utc), None);
        assert!(outside_schedule(&g, MON_0 + 13 * H, &utc));
        assert!(!outside_schedule(&g, MON_0 + 33 * H, &utc));
        // an empty day mask never opens
        g.schedule = Some(vec![w(0, 0, 60, "UTC")]);
        assert_eq!(next_open_in_s(&g, MON_0 + 13 * H, &utc), None);
        assert!(outside_schedule(&g, MON_0 + 13 * H, &utc));
    }

    use proptest::prelude::*;

    fn arb_window() -> impl Strategy<Value = Window> {
        (any::<u8>(), 0u16..1440, 0u16..=1440, "[A-Za-z/+:0-9]{1,12}").prop_map(
            |(days, start_min, end_min, tz)| Window {
                days,
                start_min,
                end_min,
                tz,
            },
        )
    }

    fn arb_tz() -> impl Strategy<Value = TableTz> {
        (
            -14 * 60..=14 * 60i32,
            proptest::collection::vec((any::<u64>(), -14 * 60..=14 * 60i32), 0..4),
        )
            .prop_map(|(initial, transitions)| TableTz::new("Fuzz/Zone", initial, transitions))
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// F3 companion: the evaluator is total over any `now: u64` (a fuzzed `Clock`
        /// reading), any window and any transition table, and its answers are sane.
        #[test]
        fn schedule_evaluation_is_total_over_the_whole_clock_range(
            windows in proptest::collection::vec(arb_window(), 0..4),
            now in any::<u64>(),
            tz in arb_tz(),
            active_from in any::<u64>(),
        ) {
            let open = is_open(&windows, now, &tz);
            if let Some(end) = current_end(&windows, now, &tz) {
                prop_assert!(open, "an end implies open");
                prop_assert!(end > now.min(MAX_NOW));
            }
            if let Some(at) = next_open_at(&windows, now, &tz) {
                prop_assert!(at >= now.min(MAX_NOW));
                if open {
                    prop_assert_eq!(at, now);
                }
            }
            let mut g = UnattendedGrant::from_preset(
                [1; 8],
                crate::id::DeviceId::from_bytes([2; 32]),
                "x",
                crate::session_log::Actor::Ui,
                crate::unattended::grant::Preset::MyMachines,
                1,
                crate::unattended::grant::AuthRecord::Pruned,
                0,
            )
            .unwrap();
            g.active_from = active_from;
            g.schedule = (!windows.is_empty()).then(|| windows.clone());
            let _ = next_open_in_s(&g, now, &tz);
            let _ = outside_schedule(&g, now, &tz);
            let _ = tz_mismatches(&windows, &tz);
        }
    }
}
