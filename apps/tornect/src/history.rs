//! What a connection leaves on this computer, under the address book's
//! history switch (`tornect_core::address_book`), on both sides of it.
//!
//! Two things are kept apart. **That a key is pinned** is trust state: a
//! pairing (and on the host an unpairing, and the reject count behind a
//! temporary ban) is written whether history is on or off. **When a peer was
//! last seen** is history: while history is off, nothing writes it.
//!
//! * Client side ([`Pins`], `known-hosts.toml`): the handshake touches the
//!   host's last-seen time on every accepted session. While history is off
//!   it works on a copy in memory, a pin it made is written back afterwards
//!   (its last-seen time set to the pairing time), and the visit is not
//!   recorded.
//! * Host side ([`DevicePins`], `trusted-devices.toml`): the handshake
//!   touches a paired device's last-seen time on every fresh session
//!   request. The host's handshakes always work on a copy in memory; at each
//!   session's start and each stream's end the trust changes are written,
//!   and the last-seen times only while history is on.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};

use tornect_core::address_book::{Day, Store};
use tornect_core::trusted::{
    KnownHost, KnownHosts, TrustedDevice, TrustedDevices, known_hosts_file,
};
use tornect_core::{DeviceId, Paths, TornectId};
use tornect_signal::fsm::host::{LiveSession, SessionEnd, SessionSink};
use tornect_signal::pairing::{KnownHostStore, TrustedDeviceStore};

/// The known hosts one connection to `host` works with.
pub struct Pins {
    store: Arc<KnownHostStore>,
    path: PathBuf,
    host: TornectId,
    /// The host's record before the handshake.
    before: Option<KnownHost>,
    /// History is kept: the store is the file itself.
    keep: bool,
    book: Store,
}

impl Pins {
    /// The known hosts for a connection to `host` from the Tornect home
    /// `paths`: the file itself while history is kept, a copy in memory
    /// while it is off.
    pub fn open(paths: &Paths, host: TornectId) -> anyhow::Result<Self> {
        let book = Store::new(paths);
        let keep = book.keeps_history();
        let path = known_hosts_file(paths);
        let hosts = KnownHosts::load(&path)?;
        let before = hosts.get(&host).cloned();
        let store = if keep {
            KnownHostStore::with(path.clone(), hosts)
        } else {
            KnownHostStore::ephemeral(hosts)
        };
        Ok(Self {
            store: Arc::new(store),
            path,
            host,
            before,
            keep,
            book,
        })
    }

    /// The store to hand the handshake.
    #[must_use]
    pub fn store(&self) -> Arc<KnownHostStore> {
        Arc::clone(&self.store)
    }

    /// Whether the host was paired before this connection.
    #[must_use]
    pub fn known(&self) -> bool {
        self.before.is_some()
    }

    /// After the handshake, however it ended: a pin it made is written to
    /// `known-hosts.toml` (with history off, from the copy in memory, its
    /// last-seen time set back to the pairing time), and a name saved for the
    /// host before it was paired is bound to the key. Nothing is written when
    /// no pin was made.
    pub fn settle(&self) -> anyhow::Result<()> {
        let Some(now) = self.store.get(&self.host) else {
            return Ok(());
        };
        let pinned = self.before.as_ref().is_none_or(|before| {
            before.host_device_pk != now.host_device_pk
                || before.paired_at != now.paired_at
                || before.label != now.label
        });
        if !pinned {
            return Ok(());
        }
        if !self.keep {
            let mut hosts = KnownHosts::load(&self.path)?;
            let mut record = now.clone();
            record.last_seen = record.paired_at;
            hosts.hosts.insert(self.host, record);
            hosts.save(&self.path)?;
        }
        self.book.bind(self.host, now.host_device_pk)?;
        Ok(())
    }

    /// A session with the host started: with history on, the visit is kept
    /// (the day, the host's pinned label as the name it declared); with it
    /// off, nothing is written. Whether it was kept.
    pub fn visited(&self) -> anyhow::Result<bool> {
        let Some(record) = self.store.get(&self.host) else {
            return Ok(false);
        };
        Ok(self.book.record_visit(
            self.host,
            record.host_device_pk,
            &record.label,
            Day::today(),
        )?)
    }
}

/// The host's paired devices for its handshakes: a copy of
/// `trusted-devices.toml` in memory, written back by [`DevicePins::settle`].
pub struct DevicePins {
    store: Arc<TrustedDeviceStore>,
    path: PathBuf,
    book: Store,
    /// The copy as it was at the last settle (or at the start).
    base: Mutex<TrustedDevices>,
}

impl DevicePins {
    /// The paired devices of the Tornect home `paths`.
    pub fn open(paths: &Paths) -> anyhow::Result<Self> {
        let path = paths.trusted_devices_file();
        let devices = TrustedDevices::load(&path)?;
        Ok(Self {
            store: Arc::new(TrustedDeviceStore::ephemeral(devices.clone())),
            path,
            book: Store::new(paths),
            base: Mutex::new(devices),
        })
    }

    /// The store to hand the host's handshakes.
    #[must_use]
    pub fn store(&self) -> Arc<TrustedDeviceStore> {
        Arc::clone(&self.store)
    }

    /// Write what the handshakes changed since the last settle, into the
    /// file as it is now (a device unpaired elsewhere stays unpaired): the
    /// devices paired and unpaired here and the ban list are trust state and
    /// always written; the devices' last-seen times only while history is
    /// on. Nothing is written when nothing of that changed. Whether the file
    /// was written.
    pub fn settle(&self) -> anyhow::Result<bool> {
        let keep = self.book.keeps_history();
        let now = self.store.snapshot();
        let mut base = self.base.lock().unwrap_or_else(PoisonError::into_inner);
        let paired: Vec<&TrustedDevice> = now
            .devices
            .iter()
            .filter(|d| {
                base.get(&d.device)
                    .is_none_or(|b| b.paired_at != d.paired_at || b.label != d.label)
            })
            .collect();
        let unpaired: Vec<DeviceId> = base
            .devices
            .iter()
            .filter(|b| now.get(&b.device).is_none())
            .map(|b| b.device)
            .collect();
        let bans = now.bans != base.bans;
        let seen: Vec<(DeviceId, u64)> = if keep {
            now.devices
                .iter()
                .filter(|d| {
                    base.get(&d.device)
                        .is_some_and(|b| b.last_seen != d.last_seen)
                })
                .map(|d| (d.device, d.last_seen))
                .collect()
        } else {
            Vec::new()
        };
        if paired.is_empty() && unpaired.is_empty() && !bans && seen.is_empty() {
            *base = now;
            return Ok(false);
        }
        let mut file = TrustedDevices::load(&self.path)?;
        for device in paired {
            file.devices.retain(|f| f.device != device.device);
            file.devices.push(TrustedDevice {
                last_seen: if keep {
                    device.last_seen
                } else {
                    device.paired_at
                },
                ..device.clone()
            });
        }
        for device in &unpaired {
            file.devices.retain(|f| f.device != *device);
        }
        if bans {
            file.bans = now.bans.clone();
        }
        for (device, at) in seen {
            if let Some(f) = file.devices.iter_mut().find(|f| f.device == device) {
                f.last_seen = f.last_seen.max(at);
            }
        }
        file.save(&self.path)?;
        *base = now;
        Ok(true)
    }
}

/// A session sink that settles the host's paired devices when a session
/// goes live (a pairing just made is written then, not only at the stream's
/// end), then hands every event on to `inner`.
pub struct Settling<S> {
    inner: S,
    pins: Arc<DevicePins>,
}

impl<S> Settling<S> {
    /// `inner`, settling `pins` at each session's start.
    pub fn new(inner: S, pins: Arc<DevicePins>) -> Self {
        Self { inner, pins }
    }
}

impl<S: SessionSink> SessionSink for Settling<S> {
    fn on_start(&self, session: &LiveSession<'_>) {
        if let Err(e) = self.pins.settle() {
            tracing::warn!(error = %format!("{e:#}"), "the paired devices could not be saved");
        }
        self.inner.on_start(session);
    }

    fn on_end(&self, session_id: &str, end: Option<&SessionEnd>) {
        self.inner.on_end(session_id, end);
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use tornect_core::{DeviceIdentity, HostIdentity};
    use tornect_signal::fsm::client::{
        ClientConfig, ClientDeps, ClientOutcome, Intent, ScriptedClientUi, connect,
    };
    use tornect_signal::fsm::host::{HostConfig, HostDeps, serve_host};
    use tornect_signal::pairing::{
        PairDecision, PairScript, ScriptedConsent, SessionDecision, SessionScript,
    };

    use super::*;

    /// Every file of `dir` with its bytes and modification time, and the
    /// directory's own modification time (a file made or removed moves it).
    type Snapshot = (Vec<(PathBuf, Vec<u8>, SystemTime)>, SystemTime);

    fn snapshot(dir: &Path) -> Snapshot {
        let mut files = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() {
                let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
                files.push((path.clone(), std::fs::read(&path).unwrap(), modified));
            }
        }
        files.sort();
        (files, std::fs::metadata(dir).unwrap().modified().unwrap())
    }

    /// Every file of `dir` gets a modification time long ago, so that any
    /// write shows.
    fn age(dir: &Path) {
        let old = UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() {
                std::fs::File::options()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .set_modified(old)
                    .unwrap();
            }
        }
    }

    /// One connection from this computer (home `paths`) to the scripted host
    /// "Desk" (host key `[9; 32]`): pairing if it is new, then a session its
    /// user allows. Returns whether the visit was kept.
    async fn connect_once(
        paths: &Paths,
        identity: &Arc<HostIdentity>,
        trusted: &Arc<TrustedDeviceStore>,
    ) -> bool {
        let consent = Arc::new(ScriptedConsent::new());
        consent.push_pairing(PairScript::Decide(PairDecision::Accept { label: None }));
        consent.push_session(SessionScript::Decide(SessionDecision::AllowOnce));
        let signer: Arc<HostIdentity> = Arc::clone(identity);
        let mut hdeps = HostDeps::headless(signer, Arc::clone(trusted));
        hdeps.consent = consent;
        let hcfg = HostConfig::new("Desk", [9; 32]);
        let (client_end, host_end) = tokio::io::duplex(64 * 1024);
        let host = tokio::spawn(async move { serve_host(host_end, &hcfg, &hdeps).await });

        let pins = Pins::open(paths, identity.id()).unwrap();
        let mut cdeps = ClientDeps::headless(pins.store());
        cdeps.ui = Arc::new(ScriptedClientUi::new(true));
        let device = DeviceIdentity::from_seed(&[0x22; 32]);
        let ccfg = ClientConfig::new(identity.id(), "Laptop");
        let outcome = connect(client_end, &ccfg, &device, &cdeps, Intent::Session).await;
        pins.settle().unwrap();
        let session = match outcome.unwrap() {
            ClientOutcome::Session(session) => session,
            other => panic!("expected a session, got {other:?}"),
        };
        let kept = pins.visited().unwrap();
        drop(session);
        host.abort();
        kept
    }

    /// With history off, a connection to a paired computer changes no file:
    /// `known-hosts.toml`, the address book and the rest keep their bytes and
    /// modification times, and nothing appears in the directory, although the
    /// handshake touched the host's last-seen time (in memory). Pairing still
    /// pins, with history off too; and with history on the visit is kept.
    #[tokio::test]
    async fn with_history_off_a_connection_leaves_the_files_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path().join("home"));
        let book = Store::new(&paths);
        book.set_history(false).unwrap();
        let identity = Arc::new(HostIdentity::from_seed(&[0x11; 32]));
        let trusted = Arc::new(TrustedDeviceStore::ephemeral(Default::default()));

        // The first connection pairs: the pin is written, without a visit.
        assert!(!connect_once(&paths, &identity, &trusted).await);
        let hosts = KnownHosts::load(&known_hosts_file(&paths)).unwrap();
        let pinned = hosts.get(&identity.id()).expect("pinned with history off");
        assert_eq!(
            (pinned.label.as_str(), pinned.host_device_pk),
            ("Desk", [9; 32])
        );
        assert_eq!(pinned.last_seen, pinned.paired_at);
        assert!(!book.recent_path().exists());

        // The second one only starts a session: no file changes at all.
        age(&paths.state_dir);
        let before = snapshot(&paths.state_dir);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!connect_once(&paths, &identity, &trusted).await);
        assert_eq!(snapshot(&paths.state_dir), before);

        // History on: the visit is kept, by day.
        book.set_history(true).unwrap();
        assert!(connect_once(&paths, &identity, &trusted).await);
        let visits = book.recent().unwrap().visits;
        assert_eq!(visits.len(), 1);
        assert_eq!((visits[0].id, visits[0].day), (identity.id(), Day::today()));
        let entry = book.load().unwrap().hosts[&identity.id()].clone();
        assert_eq!(entry.last_seen, Some(Day::today()));
        assert_eq!(entry.declared.as_deref(), Some("Desk"));
    }

    /// A name saved for a computer before it was paired is bound to the key
    /// its pairing pins, with history off as on.
    #[tokio::test]
    async fn a_name_saved_before_pairing_is_bound_at_pairing() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path().join("home"));
        let book = Store::new(&paths);
        let identity = Arc::new(HostIdentity::from_seed(&[0x33; 32]));
        book.name(identity.id(), None, "Studio laptop").unwrap();
        book.set_history(false).unwrap();
        let trusted = Arc::new(TrustedDeviceStore::ephemeral(Default::default()));
        connect_once(&paths, &identity, &trusted).await;
        let entry = book.load().unwrap().hosts[&identity.id()].clone();
        assert_eq!(entry.key, Some([9; 32]));
        assert_eq!(entry.name_for(Some(&[9; 32])), Some("Studio laptop"));
        assert_eq!((entry.first_seen, entry.last_seen), (None, None));
    }

    /// One connection to the host `identity`, whose handshakes use `pins`,
    /// from the device of `seed` with the known hosts `known` (in memory):
    /// pairing if the host is new to it, with the host's user answering
    /// `pair`, then a session the user allows. The host settles when the
    /// session is live, as its session sink does. Whether a session started.
    async fn host_side(
        identity: &Arc<HostIdentity>,
        pins: &DevicePins,
        seed: u8,
        known: &Arc<KnownHostStore>,
        pair: PairDecision,
    ) -> bool {
        let consent = Arc::new(ScriptedConsent::new());
        consent.push_pairing(PairScript::Decide(pair));
        consent.push_session(SessionScript::Decide(SessionDecision::AllowOnce));
        let signer: Arc<HostIdentity> = Arc::clone(identity);
        let mut hdeps = HostDeps::headless(signer, pins.store());
        hdeps.consent = consent;
        let hcfg = HostConfig::new("Desk", [9; 32]);
        let (client_end, host_end) = tokio::io::duplex(64 * 1024);
        let host = tokio::spawn(async move { serve_host(host_end, &hcfg, &hdeps).await });
        let mut cdeps = ClientDeps::headless(Arc::clone(known));
        cdeps.ui = Arc::new(ScriptedClientUi::new(true));
        let device = DeviceIdentity::from_seed(&[seed; 32]);
        let ccfg = ClientConfig::new(identity.id(), "Laptop");
        let outcome = connect(client_end, &ccfg, &device, &cdeps, Intent::Session).await;
        let live = matches!(outcome, Ok(ClientOutcome::Session(_)));
        pins.settle().unwrap();
        drop(outcome);
        host.abort();
        live
    }

    /// Host side, with history off: a paired device's session request writes
    /// nothing (`trusted-devices.toml` and every other file keep their bytes
    /// and modification times, and the directory is not touched), although
    /// the handshake touched the device's last-seen time in memory; a
    /// pairing and a refused pairing's ban count are still written.
    #[tokio::test]
    async fn with_history_off_a_session_request_leaves_the_host_files_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path().join("host"));
        Store::new(&paths).set_history(false).unwrap();
        let identity = Arc::new(HostIdentity::from_seed(&[0x11; 32]));
        let pins = DevicePins::open(&paths).unwrap();
        let file = paths.trusted_devices_file();

        let laptop = Arc::new(KnownHostStore::ephemeral(KnownHosts::default()));
        let other = Arc::new(KnownHostStore::ephemeral(KnownHosts::default()));

        // A new device pairs: the pairing is written, without a last-seen time.
        let accept = PairDecision::Accept { label: None };
        assert!(host_side(&identity, &pins, 0x22, &laptop, accept).await);
        let devices = TrustedDevices::load(&file).unwrap();
        assert_eq!(devices.devices.len(), 1);
        assert_eq!(devices.devices[0].label, "Laptop");
        assert_eq!(devices.devices[0].last_seen, devices.devices[0].paired_at);

        // It asks for a session again: nothing on disk changes.
        age(&paths.state_dir);
        let before = snapshot(&paths.state_dir);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(host_side(&identity, &pins, 0x22, &laptop, PairDecision::Reject).await);
        assert!(!pins.settle().unwrap());
        assert_eq!(snapshot(&paths.state_dir), before);

        // Another device's pairing is refused: its reject count is written.
        assert!(!host_side(&identity, &pins, 0x44, &other, PairDecision::Reject).await);
        let devices = TrustedDevices::load(&file).unwrap();
        assert_eq!(devices.devices.len(), 1);
        assert_eq!(devices.bans.len(), 1);
        assert_eq!(devices.bans[0].reject_count, 1);
    }
}
