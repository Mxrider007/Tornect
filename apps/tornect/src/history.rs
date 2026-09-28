//! What a connection to another computer leaves on this one, under the
//! address book's history switch (`tornect_core::address_book`).
//!
//! Two things are kept apart. **That a host key is pinned** is trust state:
//! a first pairing, or a re-pair that replaces the record, is written to
//! `known-hosts.toml` whether history is on or off, and a name saved for that
//! computer before it was paired is bound to the key just pinned. **When a
//! computer was last seen** is history: while history is off, the handshake
//! gets a copy of the known hosts in memory, so that its last-seen touch
//! (made on every accepted session) writes nothing, and the visit is not
//! recorded; the files keep their bytes and their modification times.

use std::path::PathBuf;
use std::sync::Arc;

use tornect_core::address_book::{Day, Store};
use tornect_core::trusted::{KnownHost, KnownHosts, known_hosts_file};
use tornect_core::{Paths, TornectId};
use tornect_signal::pairing::KnownHostStore;

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
        TrustedDeviceStore,
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
}
