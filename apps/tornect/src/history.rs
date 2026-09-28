//! What a connection leaves on this computer, under the address book's
//! history switch (`tornect_core::address_book`), on both sides of it.
//!
//! Two things are kept apart. **That a key is pinned** is trust state: a
//! pairing (and on the host an unpairing, and the reject count behind a
//! temporary ban) is written whether history is on or off. **When a peer was
//! last seen** is history: while history is off, nothing writes it.
//!
//! * Client side ([`Pins`], `known-hosts.toml`): the handshake touches the
//!   host's last-seen time on every accepted session. It always works on a
//!   copy in memory; afterwards a pin it made, and with history on the
//!   host's last-seen time, are merged into the file as it is then, under
//!   [`known_hosts_lock`] (so a Forget or a Clear made meanwhile stays made).
//!   While history is off a new pin's last-seen time is its pairing time,
//!   and the visit is not recorded.
//! * Host side ([`DevicePins`], `trusted-devices.toml`): the handshake
//!   touches a paired device's last-seen time on every fresh session
//!   request. The host's store is shared with the file: a pairing, an
//!   unpairing and a reject count are written the moment they happen (merged
//!   into the file as it is then), a last-seen time only while history is on.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tornect_core::address_book::{Day, Store};
use tornect_core::trusted::{KnownHost, KnownHosts, known_hosts_file};
use tornect_core::{DeviceId, Paths, TornectId};
use tornect_signal::pairing::{KeepHistory, KnownHostStore, TrustedDeviceStore};

/// Every read-modify-write of `known-hosts.toml` in this process (a
/// connection's [`Pins::settle`], Forget, Clear) holds this lock, so that two
/// of them never interleave and one never undoes the other (the M-UI-2
/// security finding F-2).
static KNOWN_HOSTS: Mutex<()> = Mutex::new(());

/// Hold the lock on `known-hosts.toml`'s writers in this process.
pub fn known_hosts_lock() -> MutexGuard<'static, ()> {
    KNOWN_HOSTS.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The known hosts one connection to `host` works with.
pub struct Pins {
    store: Arc<KnownHostStore>,
    path: PathBuf,
    host: TornectId,
    /// The host's record before the handshake.
    before: Option<KnownHost>,
    book: Store,
}

impl Pins {
    /// The known hosts for a connection to `host` from the Tornect home
    /// `paths`: a copy in memory, history on or off; [`Pins::settle`] writes
    /// what the connection changed.
    pub fn open(paths: &Paths, host: TornectId) -> anyhow::Result<Self> {
        let book = Store::new(paths);
        let path = known_hosts_file(paths);
        let hosts = KnownHosts::load(&path)?;
        let before = hosts.get(&host).cloned();
        Ok(Self {
            store: Arc::new(KnownHostStore::ephemeral(hosts)),
            path,
            host,
            before,
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

    /// After the handshake, however it ended, merged into `known-hosts.toml`
    /// as it is now (under [`known_hosts_lock`]): a pin it made (with history
    /// off, its last-seen time set back to the pairing time), and with
    /// history on the host's new last-seen time, only while the host is
    /// still in the file (a Forget made meanwhile stays made). A name saved
    /// for the host before it was paired is bound to the key a pin made.
    /// Nothing is written when neither changed.
    pub fn settle(&self) -> anyhow::Result<()> {
        let Some(now) = self.store.get(&self.host) else {
            return Ok(());
        };
        let pinned = self.before.as_ref().is_none_or(|before| {
            before.host_device_pk != now.host_device_pk
                || before.paired_at != now.paired_at
                || before.label != now.label
        });
        let keep = self.book.keeps_history();
        let seen = keep
            && self
                .before
                .as_ref()
                .is_some_and(|before| before.last_seen != now.last_seen);
        if !pinned && !seen {
            return Ok(());
        }
        {
            let _one = known_hosts_lock();
            let mut hosts = KnownHosts::load(&self.path)?;
            if pinned {
                let mut record = now.clone();
                if !keep {
                    record.last_seen = record.paired_at;
                }
                hosts.hosts.insert(self.host, record);
            } else if let Some(file) = hosts.hosts.get_mut(&self.host) {
                file.last_seen = file.last_seen.max(now.last_seen);
            } else {
                return Ok(());
            }
            hosts.save(&self.path)?;
        }
        if pinned {
            self.book.bind(self.host, now.host_device_pk)?;
        }
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

/// The host's paired devices for its handshakes: `trusted-devices.toml`,
/// shared with the rest of the app (`TrustedDeviceStore::shared`). A
/// pairing, an unpairing and a reject count are written the moment they
/// happen, merged into the file as it is then; a device's last-seen time
/// only while history is on (the switch is read at each session request).
pub struct DevicePins {
    store: Arc<TrustedDeviceStore>,
    /// The paired devices (key and label) when the window last read them.
    shown: Mutex<Vec<(DeviceId, String)>>,
}

impl DevicePins {
    /// The paired devices of the Tornect home `paths`.
    pub fn open(paths: &Paths) -> anyhow::Result<Self> {
        let book = Store::new(paths);
        let keep: KeepHistory = Arc::new(move || book.keeps_history());
        let store = TrustedDeviceStore::shared(paths.trusted_devices_file(), keep)?;
        let shown = Mutex::new(paired(&store));
        Ok(Self {
            store: Arc::new(store),
            shown,
        })
    }

    /// The store to hand the host's handshakes.
    #[must_use]
    pub fn store(&self) -> Arc<TrustedDeviceStore> {
        Arc::clone(&self.store)
    }

    /// Whether a device was paired, unpaired or relabelled since the last
    /// call (the window reads the files again then). Writes nothing: the
    /// store wrote each change when it happened.
    pub fn changed(&self) -> bool {
        let now = paired(&self.store);
        let mut shown = self.shown.lock().unwrap_or_else(PoisonError::into_inner);
        let changed = *shown != now;
        *shown = now;
        changed
    }
}

/// The paired devices of `store`: key and label.
fn paired(store: &TrustedDeviceStore) -> Vec<(DeviceId, String)> {
    store
        .snapshot()
        .devices
        .into_iter()
        .map(|d| (d.device, d.label))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use tornect_core::trusted::TrustedDevices;
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
        let pins = Pins::open(paths, identity.id()).unwrap();
        connect_with(&pins, identity, trusted).await
    }

    /// [`connect_once`] with the known hosts `pins` opened before it.
    async fn connect_with(
        pins: &Pins,
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

    /// M-UI-2 security finding F-2: with history switched on, a
    /// Forget of another computer and a Clear made while a connection runs
    /// stay made: the connection writes only its own host's record, merged
    /// into the file as it is when the handshake is over.
    #[tokio::test]
    async fn a_forget_or_clear_during_a_connection_is_never_undone() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path().join("home"));
        Store::new(&paths).set_history(true).unwrap();
        let file = known_hosts_file(&paths);
        let identity = Arc::new(HostIdentity::from_seed(&[0x11; 32]));
        let trusted = Arc::new(TrustedDeviceStore::ephemeral(Default::default()));
        // The host is paired by a first connection; two other computers are
        // pinned, one of them seen after its pairing.
        connect_once(&paths, &identity, &trusted).await;
        let (studio, attic) = (
            HostIdentity::from_seed(&[0x55; 32]).id(),
            HostIdentity::from_seed(&[0x66; 32]).id(),
        );
        let mut hosts = KnownHosts::load(&file).unwrap();
        hosts.pin(studio, "Studio", [5; 32], 1000);
        hosts.pin(attic, "Attic", [6; 32], 1000);
        hosts.touch(&attic, 2000);
        hosts.save(&file).unwrap();

        // A connection starts (its copy of the known hosts is taken), and
        // meanwhile the window forgets one computer and clears the history.
        let pins = Pins::open(&paths, identity.id()).unwrap();
        let forgot = crate::ui::book::apply(&paths, &crate::ui::book::Change::Forget(studio));
        assert!(forgot.starts_with("Forgot"), "{forgot}");
        crate::ui::book::apply(&paths, &crate::ui::book::Change::Clear);
        assert!(connect_with(&pins, &identity, &trusted).await);

        let hosts = KnownHosts::load(&file).unwrap();
        assert!(hosts.get(&studio).is_none(), "the Forget was undone");
        assert_eq!(
            hosts.get(&attic).unwrap().last_seen,
            1000,
            "the Clear was undone"
        );
        let desk = hosts.get(&identity.id()).unwrap();
        assert!(desk.last_seen >= desk.paired_at, "this connection's time");
    }

    /// History off by default (the operator's ruling of 2026-09-28): on a
    /// fresh Tornect home, where the switch was never touched, neither this
    /// computer's connections nor the host's handshakes write anything about
    /// past connections. The pins are written (trust state), at their pairing
    /// time and with no visit; after that a connection and a session request
    /// change no file at all.
    #[tokio::test]
    async fn a_fresh_home_writes_no_history() {
        let tmp = tempfile::tempdir().unwrap();
        // This computer connects.
        let paths = Paths::from_home(tmp.path().join("home"));
        let book = Store::new(&paths);
        assert!(!book.keeps_history(), "history is off on a fresh home");
        let identity = Arc::new(HostIdentity::from_seed(&[0x11; 32]));
        let trusted = Arc::new(TrustedDeviceStore::ephemeral(Default::default()));
        assert!(
            !connect_once(&paths, &identity, &trusted).await,
            "a visit was kept"
        );
        let hosts = KnownHosts::load(&known_hosts_file(&paths)).unwrap();
        let pinned = hosts.get(&identity.id()).expect("the pairing pins");
        assert_eq!(pinned.last_seen, pinned.paired_at);
        assert!(!book.recent_path().exists());
        assert!(!book.book_path().exists(), "the address book was written");
        age(&paths.state_dir);
        let before = snapshot(&paths.state_dir);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!connect_once(&paths, &identity, &trusted).await);
        assert_eq!(snapshot(&paths.state_dir), before);

        // A host answers.
        let host = Paths::from_home(tmp.path().join("host"));
        let pins = DevicePins::open(&host).unwrap();
        let laptop = Arc::new(KnownHostStore::ephemeral(KnownHosts::default()));
        let accept = PairDecision::Accept { label: None };
        assert!(host_side(&identity, &pins, 0x22, &laptop, accept).await);
        let devices = TrustedDevices::load(&host.trusted_devices_file()).unwrap();
        assert_eq!(devices.devices[0].last_seen, devices.devices[0].paired_at);
        age(&host.state_dir);
        let before = snapshot(&host.state_dir);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(host_side(&identity, &pins, 0x22, &laptop, PairDecision::Reject).await);
        assert_eq!(snapshot(&host.state_dir), before);
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
    /// `pair`, then a session the user allows. Whether a session started.
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
        assert_eq!(snapshot(&paths.state_dir), before);

        // Another device's pairing is refused: its reject count is written.
        assert!(!host_side(&identity, &pins, 0x44, &other, PairDecision::Reject).await);
        let devices = TrustedDevices::load(&file).unwrap();
        assert_eq!(devices.devices.len(), 1);
        assert_eq!(devices.bans.len(), 1);
        assert_eq!(devices.bans[0].reject_count, 1);
    }

    /// M-UI-2 security finding F-1: a pairing and a refused pairing's
    /// reject count are in `trusted-devices.toml` the moment the handshake
    /// made them, with no later settle point: a host that dies right after
    /// them (here: the store is never dropped and nothing else runs) keeps
    /// both. Its last-seen times still follow the switch.
    #[tokio::test]
    async fn a_pin_and_a_reject_count_survive_a_crash_right_after() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path().join("host"));
        let identity = Arc::new(HostIdentity::from_seed(&[0x11; 32]));
        let pins = DevicePins::open(&paths).unwrap();
        let file = paths.trusted_devices_file();
        let laptop = Arc::new(KnownHostStore::ephemeral(KnownHosts::default()));
        let other = Arc::new(KnownHostStore::ephemeral(KnownHosts::default()));

        let accept = PairDecision::Accept { label: None };
        assert!(host_side(&identity, &pins, 0x22, &laptop, accept).await);
        let devices = TrustedDevices::load(&file).unwrap();
        assert_eq!(devices.devices.len(), 1, "the pin is on disk at once");
        assert!(pins.changed(), "the window reads the files again");
        assert!(!pins.changed());

        assert!(!host_side(&identity, &pins, 0x44, &other, PairDecision::Reject).await);
        let devices = TrustedDevices::load(&file).unwrap();
        assert_eq!(devices.bans.len(), 1, "the reject count is on disk at once");
        assert_eq!(devices.bans[0].reject_count, 1);
        assert!(!pins.changed(), "no device paired or unpaired");
        // The crash: nothing flushes, nothing drops.
        std::mem::forget(pins);
    }
}
