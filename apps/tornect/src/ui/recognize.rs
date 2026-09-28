//! The device words on this computer's surfaces (`docs/PLAN.md` §B.6.1): what
//! a host sheet shows about the key asking, this computer's own two word
//! sets, the words of the address book's computers and of the paired devices,
//! and the look-alike alarm that compares an unpinned key with all of them.
//!
//! Every derivation here blocks (Argon2id over 64 MiB): run it in a blocking
//! task, never on the UI thread or a network task. A key nobody saved is
//! derived only through this computer's [`Pacer`] (W-B5): for the pairing
//! sheet about to be shown (the pairing rate limiter admitted the request
//! first) or for the connect field's check, one at a time and at most one a
//! second. The keys this computer saved are derived once each and kept in
//! memory ([`Known`]); the address book also keeps each computer's words in
//! its entry's cache. Nothing here logs, sends or stores a word anywhere else.

use tornect_core::address_book::Store;
use tornect_core::trusted::{KnownHosts, TrustedDevices, known_hosts_file};
use tornect_core::words::{self, Candidate, Identicon, Known, Pacer, Role, Saved, Words};
use tornect_core::{DeviceId, Paths, TornectId};

use super::model::{MyWords, Recognition};

/// This computer: the name it declares and its two keys.
#[derive(Debug, Clone)]
pub struct Me {
    /// The name other devices see (`general.device_name`).
    pub name: String,
    /// Its Tornect ID (the onion address).
    pub onion: TornectId,
    /// Its device key (what a host's sheet names when it connects).
    pub device: DeviceId,
}

/// The words and the alarm of one Tornect home.
#[derive(Debug, Default)]
pub struct Recognizer {
    known: Known,
    pacer: Pacer,
    /// Where the saved entries are read from; none: nothing is saved.
    paths: Option<Paths>,
    me: Option<Me>,
}

/// A computer the address book or the pin store names.
struct Named {
    id: TornectId,
    name: String,
    cached: Option<(Words, Identicon)>,
}

impl Recognizer {
    /// The words of the Tornect home `paths`, which is `me`.
    #[must_use]
    pub fn new(paths: Paths, me: Me) -> Self {
        Self {
            known: Known::default(),
            pacer: Pacer::new(),
            paths: Some(paths),
            me: Some(me),
        }
    }

    /// The keys derived so far (the saved ones).
    #[must_use]
    pub fn known(&self) -> &Known {
        &self.known
    }

    /// This computer's two word sets: its device key's and its address's.
    #[must_use]
    pub fn mine(&self) -> Option<MyWords> {
        let me = self.me.as_ref()?;
        Some(MyWords {
            device: self
                .known
                .get(me.device.public_key_bytes(), Role::Device)
                .words(),
            address: self
                .known
                .get(me.onion.public_key_bytes(), Role::Onion)
                .words(),
        })
    }

    /// What a pairing sheet shows about `device`, which declared the name
    /// `declared`: its device words; its identicon only when the key is
    /// pinned already (a re-pair, shown beside its pinned label); for an
    /// unpinned key, the saved entry it looks like, if it looks like one.
    /// An unpinned key is derived through the pacer.
    #[must_use]
    pub fn pairing_sheet(&self, device: &DeviceId, declared: &str, pinned: bool) -> Recognition {
        let key = device.public_key_bytes();
        if pinned {
            let h = self.known.get(key, Role::Device);
            return Recognition {
                words: h.words(),
                identicon: Some(h.identicon()),
                looks_like: None,
            };
        }
        let h = self.pacer.derive(key, Role::Device);
        let candidate = Candidate {
            words: h.words(),
            identicon: h.identicon(),
            declared: Some(declared),
        };
        let saved = self.saved();
        Recognition {
            words: h.words(),
            identicon: None,
            looks_like: words::look_alike(&candidate, &saved).map(|(at, _)| saved[at].name.clone()),
        }
    }

    /// What a session sheet shows about a paired device: its identicon,
    /// beside its pinned label.
    #[must_use]
    pub fn session_sheet(&self, device: &DeviceId) -> Recognition {
        let h = self.known.get(device.public_key_bytes(), Role::Device);
        Recognition {
            words: h.words(),
            identicon: Some(h.identicon()),
            looks_like: None,
        }
    }

    /// The connect field's check of `id`, an ID that is not in the address
    /// book: the name of the saved computer it looks like, if it looks like
    /// one — the same first or last four characters as a saved ID, or words
    /// that meet the alarm's rules against a saved entry. Paced.
    #[must_use]
    pub fn connect_check(&self, id: &TornectId) -> Option<String> {
        let base = id.base32();
        if let Some(named) = self
            .named()
            .into_iter()
            .find(|n| n.id != *id && words::ends_look_alike(&base, &n.id.base32()))
        {
            return Some(named.name);
        }
        let h = self.pacer.derive(id.public_key_bytes(), Role::Onion);
        let candidate = Candidate {
            words: h.words(),
            identicon: h.identicon(),
            declared: None,
        };
        let saved = self.saved();
        words::look_alike(&candidate, &saved).map(|(at, _)| saved[at].name.clone())
    }

    /// Every saved entry the alarm compares with: this computer's own two
    /// word sets (under its own name), the computers of the address book and
    /// the pin store (under their saved name or pinned label), and the
    /// paired devices (under their pinned labels). Saved keys only: each is
    /// derived once, or read from the address book's cache.
    #[must_use]
    pub fn saved(&self) -> Vec<Saved> {
        let mut saved = Vec::new();
        if let Some(me) = &self.me {
            for (key, role) in [
                (me.device.public_key_bytes(), Role::Device),
                (me.onion.public_key_bytes(), Role::Onion),
            ] {
                let h = self.known.get(key, role);
                saved.push(Saved {
                    name: me.name.clone(),
                    words: h.words(),
                    identicon: h.identicon(),
                });
            }
        }
        for named in self.named() {
            let (words, identicon) = named.cached.unwrap_or_else(|| {
                let h = self.known.get(named.id.public_key_bytes(), Role::Onion);
                (h.words(), h.identicon())
            });
            saved.push(Saved {
                name: named.name,
                words,
                identicon,
            });
        }
        if let Some(paths) = &self.paths {
            let devices = TrustedDevices::load(&paths.trusted_devices_file()).unwrap_or_default();
            for device in devices.devices {
                let h = self
                    .known
                    .get(device.device.public_key_bytes(), Role::Device);
                saved.push(Saved {
                    name: device.label,
                    words: h.words(),
                    identicon: h.identicon(),
                });
            }
        }
        saved
    }

    /// Derive every saved key not derived yet (this computer's, the address
    /// book's, the paired devices'), and keep the address book's words in its
    /// entries' caches. Whether the cache file changed.
    pub fn warm(&self) -> bool {
        let _ = self.mine();
        let _ = self.saved();
        let Some(paths) = &self.paths else {
            return false;
        };
        let store = Store::new(paths);
        let Ok(book) = store.load() else {
            return false;
        };
        let derived: Vec<_> = book
            .hosts
            .iter()
            .filter(|(id, entry)| {
                entry
                    .cached_words(id.public_key_bytes(), Role::Onion)
                    .is_none()
            })
            .map(|(id, _)| (*id, self.known.get(id.public_key_bytes(), Role::Onion)))
            .collect();
        !derived.is_empty() && store.cache_words(&derived).unwrap_or(false)
    }

    /// The computers of the address book and the pin store, with the name
    /// people know each by and the address book's cached words.
    fn named(&self) -> Vec<Named> {
        let Some(paths) = &self.paths else {
            return Vec::new();
        };
        let book = Store::new(paths).load().unwrap_or_default();
        let known = KnownHosts::load(&known_hosts_file(paths)).unwrap_or_default();
        let mut ids: Vec<TornectId> = known
            .hosts
            .keys()
            .chain(book.hosts.keys())
            .copied()
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids.into_iter()
            .map(|id| {
                let pin = known.get(&id);
                let entry = book.hosts.get(&id);
                let name = entry
                    .and_then(|e| e.name_for(pin.map(|p| &p.host_device_pk)))
                    .map(str::to_owned)
                    .or_else(|| pin.map(|p| p.label.clone()))
                    .unwrap_or_else(|| format!("{}…", id.short()));
                Named {
                    id,
                    name,
                    cached: entry.and_then(|e| e.cached_words(id.public_key_bytes(), Role::Onion)),
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::{Arc, Mutex, OnceLock, PoisonError};
    use std::time::{Duration, Instant};

    use tokio::sync::watch;
    use tornect_core::trusted::TrustedDevices;
    use tornect_core::words::{Stretched, derive};
    use tornect_core::{DeviceIdentity, HostIdentity};
    use tornect_signal::fsm::client::{
        ClientConfig, ClientDeps, ClientOutcome, Intent, ScriptedClientUi, connect,
    };
    use tornect_signal::fsm::host::{HostConfig, HostDeps, KillSwitch, serve_host};
    use tornect_signal::pairing::{
        Consent as _, KnownHostStore, PairDecision, PairingPeer, TrustedDeviceStore,
    };

    use super::super::consent::{GuiConsent, Popups, Withdraw};
    use super::super::model::{Model, Popup, PopupKind, Shared};
    use super::*;

    /// A Tornect home at `dir` with one paired device, "Office PC" (the key
    /// of seed 0x41), and the words of this computer (seeds 0x11, 0x12).
    fn home(dir: &std::path::Path) -> (Paths, Recognizer) {
        let paths = Paths::from_home(dir.join("home"));
        let mut devices = TrustedDevices::default();
        devices.pin(device(0x41), "Office PC", 1000);
        devices.save(&paths.trusted_devices_file()).unwrap();
        let me = Me {
            name: "Linux PC".to_owned(),
            onion: HostIdentity::from_seed(&[0x11; 32]).id(),
            device: device(0x12),
        };
        (paths.clone(), Recognizer::new(paths, me))
    }

    fn device(seed: u8) -> DeviceId {
        DeviceIdentity::from_seed(&[seed; 32]).id()
    }

    fn popups() -> Arc<Popups> {
        Popups::new(Shared::new(Model::default(), Arc::new(|_| {})))
    }

    fn consent(popups: &Arc<Popups>, words: Arc<Recognizer>) -> GuiConsent {
        let (_started_tx, started) = watch::channel(0);
        GuiConsent::new(
            Arc::clone(popups),
            Withdraw {
                kill: KillSwitch::new(),
                started,
                live: Arc::new(|| false),
            },
        )
        .with_words(words)
    }

    /// The first host popup on screen, once there is one.
    async fn shown(popups: &Popups) -> Popup {
        for _ in 0..2000 {
            if let Some(p) = popups.shared().read(|m| m.popups.first().cloned()) {
                return p;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("no popup shown");
    }

    fn peer(seed: u8, name: &str) -> PairingPeer {
        let device = device(seed);
        PairingPeer {
            device,
            name: name.to_owned(),
            fingerprint: device.fingerprint(),
            pinned_label: None,
        }
    }

    /// W-B8 and the sheet's name slot: an unpinned key gets its words and no
    /// identicon; a pinned key (a re-pair) and a paired device's session
    /// request get the identicon beside their saved name; no alarm for a
    /// key that looks like nothing saved.
    #[test]
    fn an_unpinned_key_gets_words_and_never_an_identicon() {
        let tmp = tempfile::tempdir().unwrap();
        let (_, words) = home(tmp.path());
        let new = words.pairing_sheet(&device(0x77), "Kitchen", false);
        let expected = derive(device(0x77).public_key_bytes(), Role::Device);
        assert_eq!(new.words, expected.words());
        assert_eq!(new.identicon, None);
        assert_eq!(new.looks_like, None);
        let pinned = words.pairing_sheet(&device(0x41), "Office PC", true);
        assert_eq!(
            pinned.identicon,
            Some(derive(device(0x41).public_key_bytes(), Role::Device).identicon())
        );
        assert_eq!(
            words.session_sheet(&device(0x41)).identicon,
            pinned.identicon
        );
    }

    /// The alarm compares with every saved entry: a new device that declares
    /// the name of a paired one, or of this computer, looks like it; the
    /// saved entries include this computer's two word sets.
    #[test]
    fn the_alarm_knows_the_saved_devices_and_this_computer() {
        let tmp = tempfile::tempdir().unwrap();
        let (_, words) = home(tmp.path());
        let saved = words.saved();
        assert_eq!(saved.len(), 3, "this computer twice, one paired device");
        assert_eq!(
            saved[0].words,
            derive(device(0x12).public_key_bytes(), Role::Device).words()
        );
        let like = words.pairing_sheet(&device(0x77), "Office  PC", false);
        assert_eq!(like.looks_like.as_deref(), Some("Office PC"));
        let me = words.pairing_sheet(&device(0x78), "linux pc", false);
        assert_eq!(me.looks_like.as_deref(), Some("Linux PC"));
    }

    /// W-B3, through the window's consent: a sheet whose alarm fired pairs
    /// only through the code typed from the other device, checked here
    /// against this computer's own code. A click's accept is a refusal
    /// (the FSM counts it toward the temp-ban), a wrong code is a refusal,
    /// the right code pairs. W-B5: each unpinned key's derivation starts at
    /// least a second after the one before.
    #[tokio::test]
    async fn a_fired_alarm_never_pairs_without_the_digits() {
        let tmp = tempfile::tempdir().unwrap();
        let (_, words) = home(tmp.path());
        let popups = popups();
        let consent = consent(&popups, Arc::new(words));
        let started = Instant::now();
        let mut shown_at = Vec::new();
        for (answer, expected) in [
            ("accept", PairDecision::Reject),
            ("654 321", PairDecision::Reject),
            ("123 456", PairDecision::Accept { label: None }),
        ] {
            let peer = peer(0x77, "Office PC");
            let asking = consent.pairing(&peer, "123 456");
            tokio::pin!(asking);
            let popup = tokio::select! {
                _ = &mut asking => panic!("answered before anyone did"),
                popup = shown(&popups) => popup,
            };
            shown_at.push(started.elapsed());
            let seen = popups
                .shared()
                .read(|m| m.recognition.get(&popup.id).cloned())
                .expect("the words came with the sheet");
            assert_eq!(seen.looks_like.as_deref(), Some("Office PC"));
            assert!(matches!(popup.kind, PopupKind::Pairing { .. }));
            if answer == "accept" {
                assert!(popups.answer_pairing(popup.id, PairDecision::Accept { label: None }));
            } else {
                assert!(popups.answer_pairing_code(popup.id, answer, None));
            }
            assert_eq!(asking.await, expected, "{answer}");
            assert!(
                popups
                    .shared()
                    .read(|m| m.recognition.is_empty() && m.popups.is_empty())
            );
        }
        // Three sheets of an unsaved key: the pacer started the three
        // derivations at least a second apart, so the third sheet cannot be
        // on screen before two seconds.
        assert!(shown_at[2] >= Duration::from_secs(2), "{shown_at:?}");
    }

    /// A sheet without an alarm pairs by the click, as before; a code typed
    /// there is checked all the same.
    #[tokio::test]
    async fn without_an_alarm_the_click_pairs() {
        let tmp = tempfile::tempdir().unwrap();
        let (_, words) = home(tmp.path());
        let popups = popups();
        let consent = consent(&popups, Arc::new(words));
        let peer = peer(0x79, "Kitchen");
        let asking = consent.pairing(&peer, "123 456");
        tokio::pin!(asking);
        let popup = tokio::select! {
            _ = &mut asking => panic!("answered early"),
            popup = shown(&popups) => popup,
        };
        let seen = popups.shared().read(|m| m.recognition[&popup.id].clone());
        assert_eq!(seen.looks_like, None);
        assert!(popups.answer_pairing(popup.id, PairDecision::Accept { label: None }));
        assert_eq!(asking.await, PairDecision::Accept { label: None });
    }

    /// Every trace line of this test binary from the first call on, at
    /// TRACE for Tornect's own crates.
    fn captured() -> Arc<Mutex<Vec<u8>>> {
        #[derive(Clone)]
        struct Capture(Arc<Mutex<Vec<u8>>>);
        impl Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        static CAPTURE: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
        Arc::clone(CAPTURE.get_or_init(|| {
            let buffer = Arc::new(Mutex::new(Vec::new()));
            let writer = Capture(Arc::clone(&buffer));
            let subscriber = tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::new(
                    "tornect=trace,tornect_core=trace,tornect_signal=trace,tornect_session=trace",
                ))
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .expect("no other subscriber in the tests");
            buffer
        }))
    }

    /// R-W1 and W-B4: at TRACE, over a pairing sheet (with the alarm, and
    /// the typed code), the handshake it answers and a connect field's
    /// check, no trace holds any device words, `h` or an identicon seed of
    /// any key involved.
    #[tokio::test]
    async fn no_trace_holds_device_words() {
        let log = captured();
        let tmp = tempfile::tempdir().unwrap();
        let (_, words) = home(tmp.path());
        let words = Arc::new(words);
        let popups = popups();
        let consent = Arc::new(consent(&popups, Arc::clone(&words)));

        // A pairing through the FSM, answered with the typed code.
        let identity = Arc::new(HostIdentity::from_seed(&[0x11; 32]));
        let signer: Arc<HostIdentity> = Arc::clone(&identity);
        let mut hdeps = HostDeps::headless(
            signer,
            Arc::new(TrustedDeviceStore::ephemeral(Default::default())),
        );
        hdeps.consent = consent;
        let hcfg = HostConfig::new("Desk", [9; 32]);
        let (client_end, host_end) = tokio::io::duplex(64 * 1024);
        let host = tokio::spawn(async move { serve_host(host_end, &hcfg, &hdeps).await });
        let answering = {
            let popups = Arc::clone(&popups);
            tokio::spawn(async move {
                let popup = shown(&popups).await;
                let PopupKind::Pairing { sas, .. } = popup.kind else {
                    panic!("a pairing sheet");
                };
                popups.answer_pairing_code(popup.id, &sas, Some("Office desk".to_owned()))
            })
        };
        let mut cdeps =
            ClientDeps::headless(Arc::new(KnownHostStore::ephemeral(Default::default())));
        cdeps.ui = Arc::new(ScriptedClientUi::new(true));
        let asking = DeviceIdentity::from_seed(&[0x77; 32]);
        let ccfg = ClientConfig::new(identity.id(), "Office PC");
        let outcome = connect(client_end, &ccfg, &asking, &cdeps, Intent::PairOnly).await;
        assert!(answering.await.unwrap(), "the sheet was answered");
        assert!(
            matches!(outcome, Ok(ClientOutcome::Paired { .. })),
            "{outcome:?}"
        );
        host.abort();

        // The connect field's check of an ID nobody saved.
        let pasted = HostIdentity::from_seed(&[0x55; 32]).id();
        let checker = Arc::clone(&words);
        let _ = tokio::task::spawn_blocking(move || checker.connect_check(&pasted))
            .await
            .unwrap();

        let text =
            String::from_utf8(log.lock().unwrap_or_else(PoisonError::into_inner).clone()).unwrap();
        assert!(text.contains("device paired"), "the capture works");
        let stretched: Vec<Stretched> = vec![
            derive(asking.id().public_key_bytes(), Role::Device),
            derive(device(0x41).public_key_bytes(), Role::Device),
            derive(device(0x12).public_key_bytes(), Role::Device),
            derive(identity.id().public_key_bytes(), Role::Onion),
            derive(pasted.public_key_bytes(), Role::Onion),
        ];
        for h in stretched {
            for form in [
                h.words().shown(),
                h.words().cached(),
                h.to_hex(),
                hex_seed(h.identicon().seed()),
            ] {
                assert!(!text.contains(&form), "a trace holds \"{form}\"");
            }
        }
    }

    fn hex_seed(seed: [u8; 3]) -> String {
        seed.iter().map(|b| format!("{b:02x}")).collect()
    }
}
