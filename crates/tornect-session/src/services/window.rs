//! The bulk window (the services design §3.4): a sender keeps at most
//! `bulk_window` bytes of file data and clipboard text beyond what the
//! receiver has credited, summed over everything it sends that way.
//!
//! - The receiver credits the bytes it has **written** (`Credit{xfer, upto}`,
//!   cumulative per transfer; transfer 0 is the sender's clipboard text):
//!   every [`credit_step`] bytes and at the end of a file. A credit is not a
//!   sync: one `sync_all` happens when the file is finished.
//! - `Complete` and `Cancel` release what a transfer still had in flight.
//! - The receiver holds the sender to the window: what arrived beyond what it
//!   credited never exceeds the window ([`Inflow::admits`]), else the stream
//!   ends with `Close{PROTOCOL}`. What it credited is never more than what
//!   the sender's own count says arrived, so a sender that keeps to its
//!   window is never refused.
//!
//! - While the host is locked (§2.3) its window is paused: nothing more is
//!   taken until it is unlocked, so downloads stall instead of failing.
//!
//! The window bounds the receiver's buffering and the delay a chat line or a
//! `Cancel` can meet behind bulk bytes (Arti already schedules the streams of
//! a circuit round-robin), and makes the progress the sender shows true
//! delivered progress.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use tokio::sync::Notify;

/// The receiver credits at least this often, in bytes written.
pub(crate) const CREDIT_STEP: u64 = 64 * 1024;

/// The transfer whose credits count the sender's clipboard bytes.
pub(crate) const CLIPBOARD: u32 = 0;

/// How many bytes a receiver writes between two credits under `window`:
/// [`CREDIT_STEP`], or half the window when that is smaller, so that a
/// sender is never left waiting for a credit that is not due yet.
pub(crate) fn credit_step(window: u64) -> u64 {
    CREDIT_STEP.min((window / 2).max(1))
}

/// Why a credit was refused: the stream ends with `Close{PROTOCOL}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BadCredit {
    /// No such transfer is sending.
    NotSending,
    /// The credit is below an earlier one, or above what was sent.
    OutOfRange,
}

/// What a transfer has sent, and what of it was credited.
#[derive(Debug, Default, Clone, Copy)]
struct Flight {
    sent: u64,
    credited: u64,
}

#[derive(Debug, Default)]
struct Flights {
    in_flight: u64,
    flights: HashMap<u32, Flight>,
    /// Nothing is taken while set.
    paused: bool,
}

/// The sender's window, shared by the stream's loop (credits, releases) and
/// its sending tasks (which wait for room).
#[derive(Debug)]
pub(crate) struct Window {
    limit: u64,
    flights: Mutex<Flights>,
    room: Notify,
}

impl Window {
    /// A window of `limit` bytes, with the clipboard's flight ([`CLIPBOARD`])
    /// open for good.
    pub(crate) fn new(limit: u32) -> Self {
        let mut flights = Flights::default();
        flights.flights.insert(CLIPBOARD, Flight::default());
        Self {
            limit: u64::from(limit),
            flights: Mutex::new(flights),
            room: Notify::new(),
        }
    }

    /// The window's size.
    #[cfg(test)]
    pub(crate) fn limit(&self) -> u64 {
        self.limit
    }

    /// Bytes sent and not yet credited, over every transfer.
    #[cfg(test)]
    pub(crate) fn in_flight(&self) -> u64 {
        self.lock().in_flight
    }

    /// Transfer `xfer` starts sending.
    pub(crate) fn open(&self, xfer: u32) {
        self.lock().flights.entry(xfer).or_default();
    }

    /// Wait until `n` more bytes of `xfer` fit in the window and it is not
    /// paused, and count them as sent: `false` when `xfer` was released
    /// meanwhile (or never opened), and then nothing is counted.
    /// Cancel-safe.
    pub(crate) async fn take(&self, xfer: u32, n: u64) -> bool {
        loop {
            let room = self.room.notified();
            tokio::pin!(room);
            room.as_mut().enable();
            {
                let mut guard = self.lock();
                let flights = &mut *guard;
                let Some(flight) = flights.flights.get_mut(&xfer) else {
                    return false;
                };
                if !flights.paused && flights.in_flight + n <= self.limit {
                    flight.sent += n;
                    flights.in_flight += n;
                    return true;
                }
            }
            room.await;
        }
    }

    /// Pause the window (the host is locked): nothing more is taken until it
    /// is resumed. What was taken already is sent.
    pub(crate) fn set_paused(&self, paused: bool) {
        self.lock().paused = paused;
        if !paused {
            self.room.notify_waiters();
        }
    }

    /// The receiver has written `upto` bytes of `xfer`.
    pub(crate) fn credit(&self, xfer: u32, upto: u64) -> Result<(), BadCredit> {
        let mut guard = self.lock();
        let flights = &mut *guard;
        let flight = flights
            .flights
            .get_mut(&xfer)
            .ok_or(BadCredit::NotSending)?;
        if upto < flight.credited || upto > flight.sent {
            return Err(BadCredit::OutOfRange);
        }
        let freed = upto - flight.credited;
        flight.credited = upto;
        flights.in_flight -= freed;
        drop(guard);
        if freed > 0 {
            self.room.notify_waiters();
        }
        Ok(())
    }

    /// Transfer `xfer` ended (`Complete`, `Cancel`): what it had in flight
    /// no longer counts, and a task waiting to send more of it hears `false`.
    pub(crate) fn release(&self, xfer: u32) {
        if xfer == CLIPBOARD {
            return;
        }
        let mut flights = self.lock();
        if let Some(flight) = flights.flights.remove(&xfer) {
            flights.in_flight -= flight.sent - flight.credited;
        }
        drop(flights);
        self.room.notify_waiters();
    }

    fn lock(&self) -> MutexGuard<'_, Flights> {
        self.flights.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The receiver's side of one direction's window: what arrived and what was
/// credited, per transfer.
#[derive(Debug)]
pub(crate) struct Inflow {
    limit: u64,
    step: u64,
}

impl Inflow {
    /// The receiver of a sender held to `window` bytes.
    pub(crate) fn new(window: u32) -> Self {
        let limit = u64::from(window);
        Self {
            limit,
            step: credit_step(limit),
        }
    }

    /// Whether `arrived` bytes beyond those credited, over every transfer of
    /// this direction, are within the window.
    pub(crate) fn admits(&self, arrived: u64) -> bool {
        arrived <= self.limit
    }

    /// Whether a credit is due once `written` of a `size`-byte transfer are
    /// written and `credited` were credited.
    pub(crate) fn due(&self, written: u64, credited: u64, size: u64) -> bool {
        written > credited && (written - credited >= self.step || written == size)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;

    /// A sender takes up to the window and then waits; a credit lets exactly
    /// what it freed through; the window sums over transfers.
    #[tokio::test]
    async fn the_window_holds_bytes_until_they_are_credited() {
        let window = Arc::new(Window::new(64 * 1024));
        assert_eq!(window.limit(), 64 * 1024);
        window.open(1);
        window.open(2);
        for _ in 0..3 {
            assert!(window.take(1, 16 * 1024).await);
        }
        assert!(window.take(2, 16 * 1024).await);
        assert_eq!(window.in_flight(), 64 * 1024);
        let waiting = tokio::spawn({
            let window = Arc::clone(&window);
            async move { window.take(2, 16 * 1024).await }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiting.is_finished(), "a full window waits");
        // A credit of transfer 1 frees room for transfer 2.
        window.credit(1, 8 * 1024).unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiting.is_finished(), "8 KiB freed, 16 KiB asked");
        window.credit(1, 16 * 1024).unwrap();
        assert!(waiting.await.unwrap());
        assert_eq!(window.in_flight(), 64 * 1024);
        // The same credit again changes nothing.
        window.credit(1, 16 * 1024).unwrap();
        assert_eq!(window.in_flight(), 64 * 1024);
    }

    /// A credit below an earlier one, above what was sent, or for no
    /// transfer is refused; the clipboard's flight is always open.
    #[tokio::test]
    async fn bad_credits_are_refused() {
        let window = Window::new(64 * 1024);
        window.open(3);
        assert!(window.take(3, 100).await);
        assert_eq!(window.credit(3, 101), Err(BadCredit::OutOfRange));
        window.credit(3, 50).unwrap();
        assert_eq!(window.credit(3, 49), Err(BadCredit::OutOfRange));
        assert_eq!(window.credit(4, 0), Err(BadCredit::NotSending));
        assert_eq!(window.credit(CLIPBOARD, 1), Err(BadCredit::OutOfRange));
        window.credit(CLIPBOARD, 0).unwrap();
        assert!(window.take(CLIPBOARD, 10).await);
        window.credit(CLIPBOARD, 10).unwrap();
        window.release(CLIPBOARD);
        assert!(
            window.take(CLIPBOARD, 10).await,
            "the clipboard's flight stays"
        );
    }

    /// A paused window takes nothing, room or not, until it is resumed; a
    /// transfer released while paused still hears `false`.
    #[tokio::test]
    async fn a_paused_window_takes_nothing_until_it_resumes() {
        let window = Arc::new(Window::new(64 * 1024));
        window.open(1);
        window.open(2);
        assert!(window.take(1, 1024).await);
        window.set_paused(true);
        let waiting = tokio::spawn({
            let window = Arc::clone(&window);
            async move { window.take(1, 1024).await }
        });
        let released = tokio::spawn({
            let window = Arc::clone(&window);
            async move { window.take(2, 1024).await }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiting.is_finished(), "paused, with room to spare");
        window.credit(1, 1024).unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiting.is_finished(), "a credit does not resume it");
        window.release(2);
        assert!(!released.await.unwrap());
        window.set_paused(false);
        assert!(waiting.await.unwrap());
        assert_eq!(window.in_flight(), 1024);
    }

    /// A released transfer's bytes no longer count, and a task waiting to
    /// send more of it hears `false`.
    #[tokio::test]
    async fn a_release_frees_the_window_and_stops_the_waiting_sender() {
        let window = Arc::new(Window::new(32 * 1024));
        window.open(1);
        window.open(2);
        assert!(window.take(1, 32 * 1024).await);
        let one = tokio::spawn({
            let window = Arc::clone(&window);
            async move { window.take(1, 1).await }
        });
        let two = tokio::spawn({
            let window = Arc::clone(&window);
            async move { window.take(2, 16 * 1024).await }
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        window.release(1);
        assert!(!one.await.unwrap(), "released while it waited");
        assert!(two.await.unwrap());
        assert_eq!(window.in_flight(), 16 * 1024);
        assert!(!window.take(1, 1).await, "released for good");
        assert_eq!(window.credit(1, 0), Err(BadCredit::NotSending));
    }

    /// The receiver's side: credits every 64 KiB under the default window,
    /// every half window under a small one, and at the end of a file.
    #[test]
    fn credits_come_every_step_and_at_the_end() {
        assert_eq!(credit_step(256 * 1024), 64 * 1024);
        assert_eq!(credit_step(16 * 1024), 8 * 1024);
        assert_eq!(credit_step(1), 1);
        let inflow = Inflow::new(256 * 1024);
        assert!(!inflow.due(64 * 1024 - 1, 0, 1 << 20));
        assert!(inflow.due(64 * 1024, 0, 1 << 20));
        assert!(!inflow.due(100 * 1024, 64 * 1024, 1 << 20));
        assert!(inflow.due(100, 0, 100), "the end");
        assert!(!inflow.due(100, 100, 100), "credited already");
        assert!(inflow.admits(256 * 1024));
        assert!(!inflow.admits(256 * 1024 + 1));
    }
}
