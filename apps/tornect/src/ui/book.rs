//! The tokio side of the address book: it reads `known-hosts.toml`,
//! `address-book.toml`, `recent.toml` and `trusted-devices.toml` into the
//! model's [`Book`], makes the changes the window asks for (forget, name,
//! save, the history switch, Clear) through `tornect_core::address_book`, and
//! checks, on a click only, whether a computer answers: one pairing-free ping
//! over Tor, never repeated and never in the background (no presence).

use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};
use tornect_core::address_book::{AddressBook, Day, Store};
use tornect_core::trusted::{KnownHosts, TrustedDevices, known_hosts_file};
use tornect_core::words::{Known, Role};
use tornect_core::{Paths, TornectId};
use tornect_signal::TorNode;

use super::model::{Book, Check, Computer, Device, UaRecord};
use crate::tor_cmd::explain;

/// How long a check waits for the computer's answer, the Tor circuit
/// included (reaching an onion service takes 5–30 s, up to a minute).
const CHECK_WAIT: Duration = Duration::from_secs(90);
/// How long the ping itself may take once the stream is open.
const PING_WAIT: Duration = Duration::from_secs(30);

/// A change to the address book the window asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// Forget the computer: its pin, its saved name, its history.
    Forget(TornectId),
    /// Name the computer (empty: remove the saved name).
    Name(TornectId, String),
    /// Keep history, or stop keeping it.
    History(bool),
    /// Clear the history.
    Clear,
}

/// Read the files of the Tornect home `paths` into what the pages show. A
/// file that cannot be read is left alone and named in
/// [`Book::problem`]; the history then counts as off. Device words come from
/// the address book's cache or from `derived` (the keys derived already); none is
/// derived here.
#[must_use]
pub fn read(paths: &Paths, today: Day, derived: Option<&Known>) -> Book {
    let mut problems = Vec::new();
    let store = Store::new(paths);
    let book = store.load().unwrap_or_else(|e| {
        problems.push(format!("the address book: {e}"));
        AddressBook {
            history: false,
            ..AddressBook::default()
        }
    });
    let known = KnownHosts::load(&known_hosts_file(paths)).unwrap_or_else(|e| {
        problems.push(format!("the paired computers: {e}"));
        KnownHosts::default()
    });
    let recent = store.recent().map(|r| r.visits).unwrap_or_else(|e| {
        problems.push(format!("the recent connections: {e}"));
        Vec::new()
    });
    let trusted = TrustedDevices::load(&paths.trusted_devices_file()).unwrap_or_else(|e| {
        problems.push(format!("the paired devices: {e}"));
        TrustedDevices::default()
    });
    // What each computer's unattended access was like (never a password).
    let unattended = tornect_core::unattended::hosts::HostsFile::load(&paths.hosts_file())
        .unwrap_or_else(|e| {
            problems.push(format!("the unattended records: {e}"));
            tornect_core::unattended::hosts::HostsFile::default()
        });

    let mut ids: Vec<TornectId> = known
        .hosts
        .keys()
        .chain(book.hosts.keys())
        .copied()
        .collect();
    ids.sort_unstable();
    ids.dedup();
    let mut computers: Vec<Computer> = ids
        .into_iter()
        .map(|id| {
            let pin = known.get(&id);
            let entry = book.hosts.get(&id);
            let pinned_key = pin.map(|p| &p.host_device_pk);
            let name = entry
                .and_then(|e| e.name_for(pinned_key))
                .map(str::to_owned);
            let key = id.public_key_bytes();
            let seen = entry
                .and_then(|e| e.cached_words(key, Role::Onion))
                .or_else(|| {
                    derived
                        .and_then(|k| k.cached(key, Role::Onion))
                        .map(|h| (h.words(), h.identicon()))
                });
            Computer {
                id,
                name_hidden: entry.is_some_and(|e| e.name.is_some()) && name.is_none(),
                name,
                pinned: pin.map(|p| p.label.clone()),
                declared: entry.and_then(|e| e.declared.clone()),
                words: seen.map(|(words, _)| words),
                // Beside a name only: a paired computer's (W-B8).
                identicon: seen
                    .filter(|_| pin.is_some())
                    .map(|(_, identicon)| identicon),
                paired: pin.map(|p| Day::from_unix(p.paired_at)),
                last_seen: entry.and_then(|e| e.last_seen),
                unattended: unattended
                    .get(&id)
                    .filter(|_| pin.is_some())
                    .map(|r| UaRecord {
                        worked_before: r.ua_worked_before,
                        remembered: r.remember,
                        control: r.control,
                    })
                    .unwrap_or_default(),
            }
        })
        .collect();
    computers.sort_by(|a, b| {
        b.last_seen
            .cmp(&a.last_seen)
            .then_with(|| a.title().to_lowercase().cmp(&b.title().to_lowercase()))
    });
    Book {
        computers,
        recent: recent.into_iter().map(|v| (v.id, v.day)).collect(),
        devices: trusted
            .devices
            .iter()
            .map(|d| {
                let h = derived.and_then(|k| k.cached(d.device.public_key_bytes(), Role::Device));
                Device {
                    id: d.device,
                    label: d.label.clone(),
                    words: h.map(|h| h.words()),
                    identicon: h.map(|h| h.identicon()),
                    paired: Day::from_unix(d.paired_at),
                    last_seen: Day::from_unix(d.last_seen),
                }
            })
            .collect(),
        history: book.history,
        today: Some(today),
        problem: (!problems.is_empty()).then(|| {
            format!(
                "Could not read {}. The file is left as it is.",
                problems.join("; ")
            )
        }),
        checks: Vec::new(),
        note: None,
    }
}

/// Make `change` in the files of `paths`; what to tell the user.
pub fn apply(paths: &Paths, change: &Change) -> String {
    let store = Store::new(paths);
    let known_file = known_hosts_file(paths);
    let done: anyhow::Result<String> = (|| match change {
        Change::Forget(id) => {
            let _one = crate::history::known_hosts_lock();
            let mut known = KnownHosts::load(&known_file)?;
            let was_paired = known.remove(id);
            if was_paired {
                known.save(&known_file)?;
            }
            store.forget(id)?;
            Ok(if was_paired {
                format!(
                    "Forgot {}…: the next connection to it compares a code again.",
                    id.short()
                )
            } else {
                format!("Removed {}… from the address book.", id.short())
            })
        }
        Change::Name(id, name) => {
            let pinned = KnownHosts::load(&known_file)?
                .get(id)
                .map(|p| p.host_device_pk);
            Ok(match store.name(*id, pinned, name)? {
                Some(kept) => format!("Saved as \"{kept}\"."),
                None => format!("{}… has no saved name now.", id.short()),
            })
        }
        Change::History(on) => {
            store.set_history(*on)?;
            Ok(if *on {
                "History is on: recent connections are kept on this computer.".to_owned()
            } else {
                "History is off: no list of recent connections is kept from now on.".to_owned()
            })
        }
        Change::Clear => {
            let _one = crate::history::known_hosts_lock();
            store.clear_history(Some(&known_file))?;
            Ok("History cleared. Saved computers stay until you forget them.".to_owned())
        }
    })();
    done.unwrap_or_else(|e| format!("That did not work: {e:#}"))
}

/// Ask once whether the computer `id` answers: a Tor circuit to it and one
/// pairing-free ping, within [`CHECK_WAIT`].
pub async fn check(node: &TorNode, id: TornectId) -> Check {
    let started = Instant::now();
    let asked = async {
        let mut stream = node.connect(&id).await.map_err(explain)?;
        ping_once(&mut stream).await?;
        if let Err(e) = stream.shutdown().await {
            tracing::debug!(error = %e, "closing the check's stream");
        }
        anyhow::Ok(())
    };
    match tokio::time::timeout(CHECK_WAIT, asked).await {
        Ok(Ok(())) => Check::Reachable {
            millis: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        },
        Ok(Err(e)) => Check::Unreachable(format!("{e:#}")),
        Err(_) => Check::Unreachable(format!(
            "no answer within {} s: it may be offline, asleep or not sharing",
            CHECK_WAIT.as_secs()
        )),
    }
}

/// Exactly one pairing-free ping on `stream` (`tornect_signal::ping`).
pub async fn ping_once<S>(stream: &mut S) -> anyhow::Result<Duration>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tokio::time::timeout(
        PING_WAIT,
        tornect_signal::ping::ping(stream, crate::tor_cmd::nonce()?),
    )
    .await
    .map_err(|_| anyhow::anyhow!("no reply within {} s", PING_WAIT.as_secs()))?
    .map_err(explain)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Check button's work: one ping, exactly, however long the host
    /// would go on answering.
    #[tokio::test]
    async fn a_check_sends_exactly_one_ping() {
        let (mut client, mut host) = tokio::io::duplex(4096);
        let answering = tokio::spawn(async move {
            let mut answered = 0;
            let served = tornect_signal::ping::serve(&mut host, |_| answered += 1).await;
            (served, answered)
        });
        ping_once(&mut client).await.unwrap();
        client.shutdown().await.unwrap();
        drop(client);
        let (served, answered) = answering.await.unwrap();
        assert_eq!(served.unwrap(), 1);
        assert_eq!(answered, 1);
    }

    /// Privacy finding P-L1: a ping's nonce is random bytes, never the
    /// wall clock (which it was, in nanoseconds, and which told the pinged
    /// host this computer's time): two nonces differ, and neither reads as a
    /// time within a day of now, in any unit from seconds to nanoseconds.
    #[test]
    fn a_ping_nonce_is_random_not_the_clock() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let (a, b) = (
            crate::tor_cmd::nonce().unwrap(),
            crate::tor_cmd::nonce().unwrap(),
        );
        assert_ne!(a, b);
        for nonce in [a, b] {
            let n = u64::from_be_bytes(nonce);
            // The old nonce was the nanoseconds XOR the sequence number (1 for
            // a Check) shifted by 48 bits: undo that too.
            for candidate in [n, n ^ (1 << 48)] {
                let c = u128::from(candidate);
                for (unit, day) in [
                    (u128::from(now.as_secs()), 86_400u128),
                    (now.as_millis(), 86_400_000),
                    (now.as_micros(), 86_400_000_000),
                    (now.as_nanos(), 86_400_000_000_000),
                ] {
                    assert!(c.abs_diff(unit) > day, "{nonce:?} reads as the time");
                }
            }
        }
    }
}
