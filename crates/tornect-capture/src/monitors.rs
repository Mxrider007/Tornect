//! Which monitor a desktop source shows (decision M1-75, the monitors design
//! §5.4.3): the monitors a backend found, numbered by position, and the one
//! the viewer chose, held by the backend's own key for it (a Windows device
//! name, an X11 RandR name atom, a test screen's index) so that a monitor
//! added, removed or made primary does not move the view. Keys stay in
//! memory: they are never logged, never sent, and left out of `Debug`.

use tornect_input::{Rect, View};

use crate::{CaptureError, Layout, MAX_MONITORS, Monitor, Selection};

/// A monitor as a backend found it.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Found<K> {
    /// The backend's own name for it.
    pub(crate) key: K,
    /// Where it lies on the desktop.
    pub(crate) rect: Rect,
    /// The desktop's primary monitor.
    pub(crate) primary: bool,
}

/// What a [`Chooser`] wants shown.
#[derive(Clone, PartialEq, Eq)]
enum Wanted<K> {
    /// The primary of two or more, else the first. Pinned to that monitor's
    /// key at the first resolve that finds one, so a later change of the
    /// primary does not move the view.
    Default,
    /// All monitors at once.
    All,
    /// The monitor with this key.
    One(K),
}

/// The choice a [`Chooser::plan`] made, taken by [`Chooser::commit`].
struct Next<K> {
    wanted: Wanted<K>,
    /// Why the monitor shown is not the one chosen, if it is not.
    why: Option<&'static str>,
}

/// The monitors of one grab and what it shows.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Resolved<K> {
    /// Numbered 1..n by position (x, then y), each cut to the space, at most
    /// one primary, at most [`MAX_MONITORS`].
    pub(crate) monitors: Vec<Monitor>,
    /// The backend's key of each monitor, in the same order; empty when
    /// nothing was found and the whole space stands for the one monitor.
    pub(crate) keys: Vec<K>,
    /// All monitors can be shown at once (two or more).
    pub(crate) all: bool,
    /// What the grab shows.
    pub(crate) shown: Selection,
    /// The rectangle to grab, inside `space`, of even width and height: what
    /// the picture shows. Empty only for a space under 2×2.
    pub(crate) grab: Rect,
    /// What the injector addresses.
    pub(crate) space: Rect,
}

impl<K> Resolved<K> {
    /// The layout a source reports for a picture of this grab.
    pub(crate) fn layout(&self) -> Layout {
        Layout {
            monitors: self.monitors.clone(),
            all: self.all,
            shown: self.shown,
            view: View::Rect {
                shown: self.grab,
                space: self.space,
            },
        }
    }
}

impl<K> std::fmt::Debug for Resolved<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resolved")
            .field("monitors", &self.monitors)
            .field("all", &self.all)
            .field("shown", &self.shown)
            .field("grab", &self.grab)
            .field("space", &self.space)
            .finish_non_exhaustive()
    }
}

/// Holds the viewer's choice across grabs and resolves it against the
/// monitors each grab finds.
pub(crate) struct Chooser<K> {
    wanted: Wanted<K>,
    /// What the last resolve showed, of how many monitors: logged when it
    /// changes.
    last: Option<(Selection, usize)>,
}

impl<K> Default for Chooser<K> {
    fn default() -> Self {
        Self {
            wanted: Wanted::Default,
            last: None,
        }
    }
}

impl<K: Clone + Eq> Chooser<K> {
    /// The monitors `found` on a desktop that spans `space`, and what to grab.
    ///
    /// Each rectangle is cut to `space`, and one with less than 2×2 left (no
    /// picture could show it) is dropped; the rest are sorted by x, then y,
    /// kept up to [`MAX_MONITORS`] and numbered 1..n, with only the first
    /// primary kept as such. Nothing found means one monitor, the whole
    /// space. All monitors are offered from two on. A choice whose monitor
    /// is gone falls back to the default (the primary of two or more, else
    /// the first), and all of them to the first when one is left; either way
    /// the choice then holds the monitor shown.
    pub(crate) fn resolve(&mut self, found: Vec<Found<K>>, space: Rect) -> Resolved<K> {
        let (resolved, next) = self.plan(found, space);
        self.commit(next, &resolved);
        resolved
    }

    /// [`Self::resolve`] for a grab that can fail: `grab` copies the
    /// rectangle the resolve chose, and the choice changes only when it
    /// succeeds. A grab that fails (a secure Windows screen shows) leaves the
    /// choice as it was, even when the monitors found meanwhile do not hold
    /// the one chosen (an enumeration that came back empty): the screen the
    /// viewer chose is shown again once the desktop can be read.
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn resolve_with<T>(
        &mut self,
        found: Vec<Found<K>>,
        space: Rect,
        grab: impl FnOnce(Rect) -> Result<T, CaptureError>,
    ) -> Result<(T, Resolved<K>), CaptureError> {
        let (resolved, next) = self.plan(found, space);
        let grabbed = grab(resolved.grab)?;
        self.commit(next, &resolved);
        Ok((grabbed, resolved))
    }

    /// What a resolve against `found` in `space` shows, and what the choice
    /// becomes once it is taken ([`Self::commit`]); changes nothing.
    fn plan(&self, found: Vec<Found<K>>, space: Rect) -> (Resolved<K>, Next<K>) {
        let (monitors, keys) = numbered(found, space);
        let n = monitors.len();
        let all = n >= 2;
        let default = if all {
            monitors.iter().position(|m| m.primary).unwrap_or(0)
        } else {
            0
        };
        // The index shown (`None`: all of them), and why it is not the one
        // chosen.
        let (index, why) = match &self.wanted {
            Wanted::Default => (Some(default), None),
            Wanted::All if all => (None, None),
            Wanted::All => (Some(0), Some("all screens need two or more")),
            Wanted::One(key) => match keys.iter().position(|k| k == key) {
                Some(index) => (Some(index), None),
                None => (Some(default), Some("the one shown before is gone")),
            },
        };
        let wanted = match index {
            Some(index) => keys
                .get(index)
                .cloned()
                .map_or(Wanted::Default, Wanted::One),
            None => self.wanted.clone(),
        };
        let shown = index.map_or(Selection::All, |index| Selection::Monitor(id_of(index)));
        let grab = even(match index {
            Some(index) => monitors[index].rect,
            None => bounding(&monitors),
        });
        (
            Resolved {
                monitors,
                keys,
                all,
                shown,
                grab,
                space,
            },
            Next { wanted, why },
        )
    }

    /// Take the choice a [`Self::plan`] made for `resolved`, and log what is
    /// shown when it changed or fell back.
    fn commit(&mut self, next: Next<K>, resolved: &Resolved<K>) {
        self.wanted = next.wanted;
        let (shown, n) = (resolved.shown, resolved.monitors.len());
        if next.why.is_some() || self.last != Some((shown, n)) {
            let what = match shown {
                Selection::All => "all".to_owned(),
                Selection::Monitor(id) => format!("id={id}"),
            };
            match next.why {
                Some(why) => tracing::info!("monitor shown {what} of={n} ({why})"),
                None => tracing::info!("monitor shown {what} of={n}"),
            }
            self.last = Some((shown, n));
        }
    }

    /// Show `selection` from the next resolve on. `last` is the latest
    /// resolve, whose numbering the viewer chose from:
    /// [`CaptureError::NoMonitor`] for an id it does not list, or all
    /// monitors (0) where it does not offer them. A refusal changes nothing.
    pub(crate) fn select(
        &mut self,
        selection: Selection,
        last: &Resolved<K>,
    ) -> Result<(), CaptureError> {
        self.wanted = match selection {
            Selection::All if last.all => Wanted::All,
            Selection::All => return Err(CaptureError::NoMonitor(0)),
            Selection::Monitor(id) => {
                let index = usize::from(id)
                    .checked_sub(1)
                    .filter(|&index| index < last.monitors.len())
                    .ok_or(CaptureError::NoMonitor(id))?;
                last.keys
                    .get(index)
                    .cloned()
                    .map_or(Wanted::Default, Wanted::One)
            }
        };
        Ok(())
    }
}

/// The monitors `found` on a desktop that spans `space`, as a [`Layout`]
/// lists them ([`Chooser::resolve`]'s rules: cut to the space, sorted by x
/// then y, at most [`MAX_MONITORS`], numbered 1..n, one primary; the whole
/// space when nothing is found), without choosing one: what a desktop
/// reports outside a session (`tornect doctor`).
// The X11 and GDI backends list a desktop; macOS has no desktop backend yet.
#[cfg_attr(not(any(target_os = "linux", windows)), allow(dead_code))]
pub(crate) fn listed<K>(found: Vec<Found<K>>, space: Rect) -> Vec<Monitor> {
    numbered(found, space).0
}

/// [`listed`], with the backend's key of each monitor found, in the same
/// order (none when the whole space stands for the one monitor).
fn numbered<K>(found: Vec<Found<K>>, space: Rect) -> (Vec<Monitor>, Vec<K>) {
    let mut found: Vec<(Rect, bool, K)> = found
        .into_iter()
        .filter_map(|f| clamped(f.rect, space).map(|rect| (rect, f.primary, f.key)))
        .collect();
    found.sort_by_key(|(rect, ..)| (rect.x, rect.y));
    found.truncate(MAX_MONITORS);
    let mut monitors = Vec::with_capacity(found.len().max(1));
    let mut keys = Vec::with_capacity(found.len());
    let mut primary_seen = false;
    for (index, (rect, primary, key)) in found.into_iter().enumerate() {
        let primary = primary && !primary_seen;
        primary_seen |= primary;
        monitors.push(Monitor {
            id: id_of(index),
            primary,
            rect,
        });
        keys.push(key);
    }
    if monitors.is_empty() {
        monitors.push(Monitor {
            id: 1,
            primary: false,
            rect: space,
        });
    }
    (monitors, keys)
}

/// The id of the monitor at `index` (from 0) of a list.
fn id_of(index: usize) -> u8 {
    u8::try_from(index + 1).unwrap_or(u8::MAX)
}

/// `rect` cut to `space`; `None` when less than 2×2 is left, since a picture
/// shows only an even part.
fn clamped(rect: Rect, space: Rect) -> Option<Rect> {
    let end = |at: i32, len: u32| i64::from(at) + i64::from(len);
    let left = rect.x.max(space.x);
    let top = rect.y.max(space.y);
    let right = end(rect.x, rect.width).min(end(space.x, space.width));
    let bottom = end(rect.y, rect.height).min(end(space.y, space.height));
    let width = u32::try_from(right - i64::from(left)).ok()?;
    let height = u32::try_from(bottom - i64::from(top)).ok()?;
    (width >= 2 && height >= 2).then_some(Rect::new(left, top, width, height))
}

/// The even part of `rect`: its last column or row dropped when odd.
fn even(rect: Rect) -> Rect {
    Rect::new(rect.x, rect.y, rect.width & !1, rect.height & !1)
}

/// The smallest rectangle holding every monitor.
fn bounding(monitors: &[Monitor]) -> Rect {
    let edges = |m: &Monitor| {
        let (x, y) = (i64::from(m.rect.x), i64::from(m.rect.y));
        (
            x,
            y,
            x + i64::from(m.rect.width),
            y + i64::from(m.rect.height),
        )
    };
    let Some((mut left, mut top, mut right, mut bottom)) = monitors.first().map(edges) else {
        return Rect::default();
    };
    for (l, t, r, b) in monitors.iter().map(edges) {
        (left, top) = (left.min(l), top.min(t));
        (right, bottom) = (right.max(r), bottom.max(b));
    }
    // Every edge lies inside a space of `i32` corners and `u32` sides.
    Rect::new(
        i32::try_from(left).unwrap_or(i32::MIN),
        i32::try_from(top).unwrap_or(i32::MIN),
        u32::try_from(right - left).unwrap_or(0),
        u32::try_from(bottom - top).unwrap_or(0),
    )
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;

    use super::*;
    use crate::{TestCard, VideoSource};

    fn found(key: &'static str, x: i32, y: i32, width: u32, height: u32) -> Found<&'static str> {
        Found {
            key,
            rect: Rect::new(x, y, width, height),
            primary: false,
        }
    }

    fn primary(mut f: Found<&'static str>) -> Found<&'static str> {
        f.primary = true;
        f
    }

    /// A 1920×1080 primary with a 1280×1024 monitor right of it and a
    /// 1920×1080 one left of it, at negative x (a Windows virtual desktop).
    fn three() -> Vec<Found<&'static str>> {
        vec![
            primary(found("main", 0, 0, 1920, 1080)),
            found("right", 1920, 0, 1280, 1024),
            found("left", -1920, 0, 1920, 1080),
        ]
    }

    const THREE_SPACE: Rect = Rect::new(-1920, 0, 5120, 1080);

    fn ids_and_rects(r: &Resolved<&'static str>) -> Vec<(u8, bool, Rect)> {
        r.monitors
            .iter()
            .map(|m| (m.id, m.primary, m.rect))
            .collect()
    }

    /// Monitors are sorted by x, then y, and numbered from 1, whatever order
    /// the backend found them in; their keys follow them.
    #[test]
    fn monitors_are_sorted_by_x_then_y_and_numbered_from_1() {
        let mut chooser = Chooser::default();
        let mut list = three();
        list.push(found("below", 0, 1080, 1920, 1080));
        let space = Rect::new(-1920, 0, 5120, 2160);
        let r = chooser.resolve(list, space);
        assert_eq!(
            ids_and_rects(&r),
            [
                (1, false, Rect::new(-1920, 0, 1920, 1080)),
                (2, true, Rect::new(0, 0, 1920, 1080)),
                (3, false, Rect::new(0, 1080, 1920, 1080)),
                (4, false, Rect::new(1920, 0, 1280, 1024)),
            ]
        );
        assert_eq!(r.keys, ["left", "main", "below", "right"]);
        assert!(r.all);
        assert_eq!(r.space, space);
    }

    /// What a desktop reports outside a session is the list a layout of
    /// the same monitors has, cut, sorted and numbered alike, and the whole
    /// space when nothing is found.
    #[test]
    fn a_listing_numbers_the_monitors_as_a_layout_does() {
        let space = Rect::new(-1920, 0, 5120, 1080);
        let mut list = three();
        list.push(found("away", 9000, 0, 1920, 1080));
        assert_eq!(
            listed(list.clone(), space),
            Chooser::default().resolve(list, space).monitors
        );
        let whole = Rect::new(0, 0, 1280, 720);
        assert_eq!(
            listed(Vec::<Found<&str>>::new(), whole),
            [Monitor {
                id: 1,
                primary: false,
                rect: whole,
            }]
        );
    }

    /// Of two or more, the primary is shown first, wherever it lies.
    #[test]
    fn the_primary_is_shown_by_default() {
        let mut chooser = Chooser::default();
        let r = chooser.resolve(three(), THREE_SPACE);
        assert_eq!(r.shown, Selection::Monitor(2));
        assert_eq!(r.grab, Rect::new(0, 0, 1920, 1080));
        assert_eq!(
            r.layout(),
            Layout {
                monitors: r.monitors.clone(),
                all: true,
                shown: Selection::Monitor(2),
                view: View::Rect {
                    shown: Rect::new(0, 0, 1920, 1080),
                    space: THREE_SPACE,
                },
            }
        );
    }

    /// With no primary (Xvfb marks none), monitor 1 is shown.
    #[test]
    fn without_a_primary_monitor_1_is_shown() {
        let mut chooser = Chooser::default();
        let list = vec![found("b", 1280, 0, 1024, 768), found("a", 0, 0, 1280, 720)];
        let r = chooser.resolve(list, Rect::new(0, 0, 2304, 768));
        assert_eq!(r.shown, Selection::Monitor(1));
        assert_eq!(r.grab, Rect::new(0, 0, 1280, 720));
        assert!(r.monitors.iter().all(|m| !m.primary));
    }

    /// The view holds the monitor first shown: another monitor made primary
    /// later does not move it, though the list marks the new primary.
    #[test]
    fn a_new_primary_does_not_move_the_view() {
        let mut chooser = Chooser::default();
        assert_eq!(
            chooser.resolve(three(), THREE_SPACE).shown,
            Selection::Monitor(2)
        );
        let moved = vec![
            found("main", 0, 0, 1920, 1080),
            found("right", 1920, 0, 1280, 1024),
            primary(found("left", -1920, 0, 1920, 1080)),
        ];
        let r = chooser.resolve(moved, THREE_SPACE);
        assert_eq!(r.shown, Selection::Monitor(2));
        assert_eq!(r.grab, Rect::new(0, 0, 1920, 1080));
        assert_eq!(
            r.monitors.iter().map(|m| m.primary).collect::<Vec<_>>(),
            [true, false, false]
        );
    }

    /// One monitor offers no "all"; asking for it is `NoMonitor(0)` and
    /// changes nothing.
    #[test]
    fn one_monitor_offers_no_all() {
        let mut chooser = Chooser::default();
        let r = chooser.resolve(
            vec![primary(found("only", 0, 0, 2560, 1440))],
            Rect::new(0, 0, 2560, 1440),
        );
        assert!(!r.all);
        assert_eq!(r.shown, Selection::Monitor(1));
        assert!(matches!(
            chooser.select(Selection::All, &r),
            Err(CaptureError::NoMonitor(0))
        ));
        assert_eq!(
            chooser
                .resolve(
                    vec![primary(found("only", 0, 0, 2560, 1440))],
                    Rect::new(0, 0, 2560, 1440)
                )
                .shown,
            Selection::Monitor(1)
        );
    }

    /// Nothing found, or nothing inside the space, is one monitor: the whole
    /// space, grabbed over its even part, with no key to pin.
    #[test]
    fn nothing_found_is_the_whole_space() {
        let space = Rect::new(0, 0, 1921, 1081);
        for list in [Vec::new(), vec![found("away", 5000, 0, 1920, 1080)]] {
            let mut chooser = Chooser::default();
            let r = chooser.resolve(list, space);
            assert_eq!(ids_and_rects(&r), [(1, false, space)]);
            assert!(r.keys.is_empty());
            assert!(!r.all);
            assert_eq!(r.shown, Selection::Monitor(1));
            assert_eq!(r.grab, Rect::new(0, 0, 1920, 1080));
            assert_eq!(chooser.select(Selection::Monitor(1), &r).ok(), Some(()));
            // Monitors that appear later are chosen from as at the start.
            let r = chooser.resolve(three(), THREE_SPACE);
            assert_eq!(r.shown, Selection::Monitor(2));
        }
    }

    /// Each rectangle is cut to the space, one with less than 2×2 left is
    /// dropped, and what is grabbed has even sides, while the list keeps the
    /// cut rectangle.
    #[test]
    fn rectangles_are_cut_to_the_space_and_grabbed_even() {
        let space = Rect::new(0, 0, 3000, 1081);
        let list = vec![
            found("odd", 0, 0, 1921, 1081),
            found("over", 1921, -100, 1500, 1300),
            found("sliver", 2999, 0, 1, 1081),
            found("flat", 0, 1080, 1921, 50),
        ];
        let mut chooser = Chooser::default();
        let r = chooser.resolve(list, space);
        assert_eq!(
            ids_and_rects(&r),
            [
                (1, false, Rect::new(0, 0, 1921, 1081)),
                (2, false, Rect::new(1921, 0, 1079, 1081)),
            ]
        );
        assert_eq!(r.grab, Rect::new(0, 0, 1920, 1080));
        chooser.select(Selection::Monitor(2), &r).unwrap();
        let r = chooser.resolve(
            vec![
                found("odd", 0, 0, 1921, 1081),
                found("over", 1921, -100, 1500, 1300),
            ],
            space,
        );
        assert_eq!(r.grab, Rect::new(1921, 0, 1078, 1080));
        chooser.select(Selection::All, &r).unwrap();
        let r = chooser.resolve(
            vec![
                found("odd", 0, 0, 1921, 1081),
                found("over", 1921, -100, 1500, 1300),
            ],
            space,
        );
        assert_eq!(r.grab, Rect::new(0, 0, 3000, 1080));
        for m in &r.monitors {
            assert!(space.contains(&m.rect), "{m:?}");
        }
    }

    /// At most 16 monitors are listed: the first 16 by position.
    #[test]
    fn at_most_16_monitors_are_listed() {
        let list: Vec<Found<&'static str>> = (0..20)
            .rev()
            .map(|i| found("k", i * 100, 0, 100, 100))
            .collect();
        let mut chooser = Chooser::default();
        let r = chooser.resolve(list, Rect::new(0, 0, 2000, 100));
        assert_eq!(r.monitors.len(), MAX_MONITORS);
        assert_eq!(r.keys.len(), MAX_MONITORS);
        assert_eq!(r.monitors[15].id, 16);
        assert_eq!(r.monitors[15].rect, Rect::new(1500, 0, 100, 100));
        chooser.select(Selection::All, &r).unwrap();
        let r = chooser.resolve(
            (0..20).map(|i| found("k", i * 100, 0, 100, 100)).collect(),
            Rect::new(0, 0, 2000, 100),
        );
        assert_eq!(r.grab, Rect::new(0, 0, 1600, 100));
    }

    /// Only the first primary, by position, is kept as such.
    #[test]
    fn a_second_primary_is_not_one() {
        let list = vec![
            primary(found("b", 1920, 0, 1920, 1080)),
            primary(found("a", 0, 0, 1920, 1080)),
        ];
        let r = Chooser::default().resolve(list, Rect::new(0, 0, 3840, 1080));
        assert_eq!(
            r.monitors.iter().map(|m| m.primary).collect::<Vec<_>>(),
            [true, false]
        );
        assert_eq!(r.shown, Selection::Monitor(1));
    }

    /// An id the last list does not have, 0 among them, is `NoMonitor` with
    /// that id, and the view stays.
    #[test]
    fn an_unknown_id_is_no_monitor() {
        let mut chooser = Chooser::default();
        let r = chooser.resolve(three(), THREE_SPACE);
        for id in [0, 4, 16, 17, u8::MAX] {
            assert!(
                matches!(
                    chooser.select(Selection::Monitor(id), &r),
                    Err(CaptureError::NoMonitor(n)) if n == id
                ),
                "{id}"
            );
        }
        assert_eq!(
            chooser.resolve(three(), THREE_SPACE).shown,
            Selection::Monitor(2)
        );
    }

    /// A selection shows from the next resolve on: one monitor at its
    /// rectangle, all of them at their bounding box, even.
    #[test]
    fn a_selection_is_shown_from_the_next_resolve() {
        let mut chooser = Chooser::default();
        let r = chooser.resolve(three(), THREE_SPACE);
        chooser.select(Selection::Monitor(3), &r).unwrap();
        let r = chooser.resolve(three(), THREE_SPACE);
        assert_eq!(r.shown, Selection::Monitor(3));
        assert_eq!(r.grab, Rect::new(1920, 0, 1280, 1024));
        chooser.select(Selection::All, &r).unwrap();
        let r = chooser.resolve(three(), THREE_SPACE);
        assert_eq!(r.shown, Selection::All);
        assert_eq!(r.grab, Rect::new(-1920, 0, 5120, 1080));
        assert_eq!(
            r.layout().view,
            View::Rect {
                shown: Rect::new(-1920, 0, 5120, 1080),
                space: THREE_SPACE,
            }
        );
        chooser.select(Selection::Monitor(1), &r).unwrap();
        let r = chooser.resolve(three(), THREE_SPACE);
        assert_eq!(r.grab, Rect::new(-1920, 0, 1920, 1080));
    }

    /// The monitor shown is followed by its key: when the list renumbers
    /// around it, its new id is shown; when it is gone, the default is, and
    /// stays shown when the monitor comes back.
    #[test]
    fn a_vanished_monitor_falls_back_to_the_default() {
        let mut chooser = Chooser::default();
        let r = chooser.resolve(three(), THREE_SPACE);
        chooser.select(Selection::Monitor(3), &r).unwrap();
        assert_eq!(
            chooser.resolve(three(), THREE_SPACE).shown,
            Selection::Monitor(3)
        );
        // "left" unplugged: "right" is now monitor 2.
        let without_left = vec![
            primary(found("main", 0, 0, 1920, 1080)),
            found("right", 1920, 0, 1280, 1024),
        ];
        let r = chooser.resolve(without_left.clone(), Rect::new(0, 0, 3200, 1080));
        assert_eq!(r.shown, Selection::Monitor(2));
        assert_eq!(r.grab, Rect::new(1920, 0, 1280, 1024));
        // "right" unplugged: the primary.
        let r = chooser.resolve(three()[..1].to_vec(), Rect::new(0, 0, 1920, 1080));
        assert_eq!(r.shown, Selection::Monitor(1));
        assert_eq!(r.grab, Rect::new(0, 0, 1920, 1080));
        // Back again: the view stays on the primary.
        let r = chooser.resolve(without_left, Rect::new(0, 0, 3200, 1080));
        assert_eq!(r.shown, Selection::Monitor(1));
        // With no primary the fallback is monitor 1.
        let mut chooser = Chooser::default();
        let list = vec![
            found("a", 0, 0, 1280, 720),
            found("b", 1280, 0, 1024, 768),
            found("c", 2304, 0, 800, 600),
        ];
        let r = chooser.resolve(list, Rect::new(0, 0, 3104, 768));
        chooser.select(Selection::Monitor(2), &r).unwrap();
        let r = chooser.resolve(
            vec![found("a", 0, 0, 1280, 720), found("c", 2304, 0, 800, 600)],
            Rect::new(0, 0, 3104, 768),
        );
        assert_eq!(r.shown, Selection::Monitor(1));
    }

    /// A resolve whose grab fails changes nothing: neither an empty list nor
    /// one without the monitor chosen drops the choice, and the grab was asked
    /// for what that resolve would show (with nothing found, the whole
    /// space). A grab that succeeds takes the resolve, a fallback included,
    /// as [`Chooser::resolve`] does.
    #[test]
    fn a_failed_grab_keeps_the_choice() {
        let failed = || CaptureError::Failed("a secure screen shows".to_owned());
        let mut chooser = Chooser::default();
        let r = chooser.resolve(three(), THREE_SPACE);
        chooser.select(Selection::Monitor(3), &r).unwrap();
        let mut asked = Vec::new();
        for list in [Vec::new(), three()[..1].to_vec()] {
            let r = chooser.resolve_with(list, THREE_SPACE, |rect| {
                asked.push(rect);
                Err::<(), _>(failed())
            });
            assert!(r.is_err());
        }
        assert_eq!(
            asked,
            [THREE_SPACE, Rect::new(0, 0, 1920, 1080)],
            "what each resolve would have shown"
        );
        let (grabbed, r) = chooser
            .resolve_with(three(), THREE_SPACE, Ok::<Rect, CaptureError>)
            .unwrap();
        assert_eq!(r.shown, Selection::Monitor(3), "still the one chosen");
        assert_eq!(grabbed, Rect::new(1920, 0, 1280, 1024));

        // A grab that succeeds without the monitor chosen falls back, and
        // the fallback holds.
        let (_, r) = chooser
            .resolve_with(three()[..1].to_vec(), THREE_SPACE, Ok::<Rect, CaptureError>)
            .unwrap();
        assert_eq!(r.shown, Selection::Monitor(1));
        assert_eq!(
            chooser.resolve(three(), THREE_SPACE).shown,
            Selection::Monitor(2)
        );
    }

    /// All screens with one monitor left show it, and keep showing it when a
    /// second comes back.
    #[test]
    fn all_with_one_monitor_left_shows_it() {
        let mut chooser = Chooser::default();
        let r = chooser.resolve(three(), THREE_SPACE);
        chooser.select(Selection::All, &r).unwrap();
        assert_eq!(chooser.resolve(three(), THREE_SPACE).shown, Selection::All);
        let one = vec![found("right", 1920, 0, 1280, 1024)];
        let r = chooser.resolve(one, Rect::new(1920, 0, 1280, 1024));
        assert!(!r.all);
        assert_eq!(r.shown, Selection::Monitor(1));
        assert_eq!(r.grab, Rect::new(1920, 0, 1280, 1024));
        let r = chooser.resolve(three(), THREE_SPACE);
        assert_eq!(r.shown, Selection::Monitor(3));
    }

    /// A refused selection changes nothing: the view stays where it was.
    #[test]
    fn a_refused_selection_changes_nothing() {
        let mut chooser = Chooser::default();
        let r = chooser.resolve(three(), THREE_SPACE);
        chooser.select(Selection::Monitor(3), &r).unwrap();
        let r = chooser.resolve(three(), THREE_SPACE);
        assert!(chooser.select(Selection::Monitor(9), &r).is_err());
        assert_eq!(
            chooser.resolve(three(), THREE_SPACE).shown,
            Selection::Monitor(3)
        );
    }

    /// `Debug` of a resolve leaves the keys out: a device name or RandR name
    /// never reaches a log through it.
    #[test]
    fn the_keys_stay_out_of_debug() {
        let r = Chooser::default().resolve(
            vec![
                primary(found("DISPLAY-SECRET-1", 0, 0, 1920, 1080)),
                found("DISPLAY-SECRET-2", 1920, 0, 1920, 1080),
            ],
            Rect::new(0, 0, 3840, 1080),
        );
        let shown = format!("{r:?}");
        assert!(!shown.contains("SECRET"), "{shown}");
        assert!(shown.contains("grab"), "{shown}");
    }

    /// A source with one picture (the test card) describes no layout and
    /// refuses every selection, as the trait's defaults do.
    #[test]
    fn a_source_with_one_picture_has_no_layout() {
        let mut card = TestCard::new(256, 96, 1000);
        card.next_frame(Duration::from_secs(1)).unwrap();
        assert_eq!(card.layout(), None);
        let stop = AtomicBool::new(false);
        for selection in [Selection::All, Selection::Monitor(1)] {
            assert!(matches!(
                card.select(selection, &stop),
                Err(CaptureError::Unavailable(_))
            ));
        }
    }
}
