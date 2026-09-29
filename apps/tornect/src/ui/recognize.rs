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

use std::sync::atomic::AtomicBool;

use tornect_core::address_book::Store;
use tornect_core::trusted::{KnownHosts, TrustedDevices, known_hosts_file};
use tornect_core::words::{
    self, Candidate, Identicon, Known, Pacer, Role, Saved, Stretched, Words,
};
use tornect_core::{DeviceId, Paths, TornectId};

use super::model::{MyWords, Recognition};

/// This computer: the name it declares and its two keys.
#[derive(Clone)]
pub struct Me {
    /// The name other devices see (`general.device_name`).
    pub name: String,
    /// Its Tornect ID (the onion address).
    pub onion: TornectId,
    /// Its device key (what a host's sheet names when it connects).
    pub device: DeviceId,
}

impl std::fmt::Debug for Me {
    /// Neither the name nor the keys: a debug line never names this computer.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Me").finish_non_exhaustive()
    }
}

/// The words and the alarm of one Tornect home.
#[derive(Default)]
pub struct Recognizer {
    known: Known,
    pacer: Pacer,
    /// Where the saved entries are read from; none: nothing is saved.
    paths: Option<Paths>,
    me: Option<Me>,
}

impl std::fmt::Debug for Recognizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Recognizer").finish_non_exhaustive()
    }
}

/// A computer the address book or the pin store names.
struct Named {
    id: TornectId,
    /// Every name it is known by, the one lists show first: its saved name
    /// where it applies, its pinned label, the name it last declared (the
    /// start of its ID when it has none).
    names: Vec<String>,
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
    #[cfg(test)]
    #[must_use]
    pub fn pairing_sheet(&self, device: &DeviceId, declared: &str, pinned: bool) -> Recognition {
        let key = device.public_key_bytes();
        if pinned {
            return self.pinned_sheet(key);
        }
        self.unpinned_sheet(self.pacer.derive(key, Role::Device), declared)
    }

    /// What a pairing sheet shows about `device` (as `pairing_sheet` in the
    /// tests), unless `gone` is set before the pacer's turn comes for an
    /// unpinned key: the request was withdrawn or timed out while it
    /// queued, and nothing is derived for it (`None`, F-3).
    #[must_use]
    pub fn pairing_sheet_unless(
        &self,
        gone: &AtomicBool,
        device: &DeviceId,
        declared: &str,
        pinned: bool,
    ) -> Option<Recognition> {
        let key = device.public_key_bytes();
        if pinned {
            return Some(self.pinned_sheet(key));
        }
        let h = self.pacer.derive_unless(gone, key, Role::Device)?;
        Some(self.unpinned_sheet(h, declared))
    }

    /// The pacer every key nobody saved is derived through.
    #[cfg(test)]
    #[must_use]
    pub fn pacer(&self) -> &Pacer {
        &self.pacer
    }

    fn pinned_sheet(&self, key: &[u8; 32]) -> Recognition {
        let h = self.known.get(key, Role::Device);
        Recognition {
            words: h.words(),
            identicon: Some(h.identicon()),
            looks_like: None,
            unchecked: false,
        }
    }

    /// An unpinned key's sheet: its words, and the alarm against every saved
    /// entry. When a file holding saved entries could not be read and none of
    /// the entries that could be read matches, the alarm could not compare,
    /// and it counts as fired (F-4): the sheet then takes only the typed code.
    fn unpinned_sheet(&self, h: Stretched, declared: &str) -> Recognition {
        let candidate = Candidate {
            words: h.words(),
            identicon: h.identicon(),
            declared: Some(declared),
        };
        let (saved, complete) = self.saved_set();
        let looks_like =
            words::look_alike(&candidate, &saved).map(|(at, _)| saved[at].name.clone());
        Recognition {
            words: h.words(),
            identicon: None,
            unchecked: looks_like.is_none() && !complete,
            looks_like,
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
            unchecked: false,
        }
    }

    /// The connect field's check of `id`, an ID that is not in the address
    /// book: the name of the saved computer it looks like, if it looks like
    /// one — the same first or last four characters as a saved ID, or words
    /// that meet the alarm's rules against a saved entry. Paced.
    ///
    /// When a file holding saved entries could not be read and nothing that
    /// could be read matches, the answer is [`Lookalike::Unchecked`]: the
    /// field warns that it could not compare (F-4), never silently passes.
    #[must_use]
    pub fn connect_check(&self, id: &TornectId) -> Option<Lookalike> {
        let base = id.base32();
        let (named, named_complete) = self.named();
        if let Some(mut named) = named
            .into_iter()
            .find(|n| n.id != *id && words::ends_look_alike(&base, &n.id.base32()))
        {
            return Some(Lookalike::Named(named.names.swap_remove(0)));
        }
        let h = self.pacer.derive(id.public_key_bytes(), Role::Onion);
        let candidate = Candidate {
            words: h.words(),
            identicon: h.identicon(),
            declared: None,
        };
        let (saved, complete) = self.saved_set();
        match words::look_alike(&candidate, &saved) {
            Some((at, _)) => Some(Lookalike::Named(saved[at].name.clone())),
            None if !(complete && named_complete) => Some(Lookalike::Unchecked),
            None => None,
        }
    }

    /// Every saved entry the alarm compares with: this computer's own two
    /// word sets (under its own name), the computers of the address book and
    /// the pin store (once under each name each is known by: its saved name,
    /// its pinned label, the name it last declared), and the paired devices
    /// (under their pinned labels). Saved keys only: each is
    /// derived once, or read from the address book's cache.
    #[must_use]
    pub fn saved(&self) -> Vec<Saved> {
        self.saved_set().0
    }

    /// [`Self::saved`], and whether every file holding saved entries could be
    /// read (`false`: a damaged or unreadable address book, pin store or
    /// paired-device file left its entries out, F-4).
    #[must_use]
    pub fn saved_set(&self) -> (Vec<Saved>, bool) {
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
        let (named, mut complete) = self.named();
        for named in named {
            let (words, identicon) = named.cached.unwrap_or_else(|| {
                let h = self.known.get(named.id.public_key_bytes(), Role::Onion);
                (h.words(), h.identicon())
            });
            for name in named.names {
                saved.push(Saved {
                    name,
                    words,
                    identicon,
                });
            }
        }
        if let Some(paths) = &self.paths {
            let devices =
                TrustedDevices::load(&paths.trusted_devices_file()).unwrap_or_else(|_| {
                    complete = false;
                    TrustedDevices::default()
                });
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
        (saved, complete)
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
    /// people know each by and the address book's cached words; and whether
    /// both files could be read.
    fn named(&self) -> (Vec<Named>, bool) {
        let Some(paths) = &self.paths else {
            return (Vec::new(), true);
        };
        let mut complete = true;
        let book = Store::new(paths).load().unwrap_or_else(|_| {
            complete = false;
            Default::default()
        });
        let known = KnownHosts::load(&known_hosts_file(paths)).unwrap_or_else(|_| {
            complete = false;
            KnownHosts::default()
        });
        let mut ids: Vec<TornectId> = known
            .hosts
            .keys()
            .chain(book.hosts.keys())
            .copied()
            .collect();
        ids.sort_unstable();
        ids.dedup();
        let named = ids
            .into_iter()
            .map(|id| {
                let pin = known.get(&id);
                let entry = book.hosts.get(&id);
                let mut names: Vec<String> = Vec::new();
                for name in [
                    entry
                        .and_then(|e| e.name_for(pin.map(|p| &p.host_device_pk)))
                        .map(str::to_owned),
                    pin.map(|p| p.label.clone()),
                    entry.and_then(|e| e.declared.clone()),
                ]
                .into_iter()
                .flatten()
                {
                    if !names.contains(&name) {
                        names.push(name);
                    }
                }
                if names.is_empty() {
                    names.push(format!("{}…", id.short()));
                }
                Named {
                    id,
                    names,
                    cached: entry.and_then(|e| e.cached_words(id.public_key_bytes(), Role::Onion)),
                }
            })
            .collect();
        (named, complete)
    }
}

/// A flag set when its owner is dropped: a pairing answer that is dropped
/// before its paced derivation started cancels it (F-3).
#[derive(Debug, Default)]
pub(crate) struct GoneOnDrop(std::sync::Arc<AtomicBool>);

impl GoneOnDrop {
    /// The flag, for the blocking task.
    pub(crate) fn flag(&self) -> std::sync::Arc<AtomicBool> {
        std::sync::Arc::clone(&self.0)
    }
}

impl Drop for GoneOnDrop {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::Release);
    }
}

/// What the connect field's check found about an ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookalike {
    /// It looks like this saved computer.
    Named(String),
    /// A file holding saved entries could not be read, so it could not be
    /// compared with all of them (F-4).
    Unchecked,
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

    /// The alarm compares a saved computer under every name it is known by:
    /// a device declaring a computer's pinned label fires it although the
    /// computer has a saved name of its own.
    #[test]
    fn every_name_of_a_saved_computer_is_compared() {
        let tmp = tempfile::tempdir().unwrap();
        let (paths, words) = home(tmp.path());
        let host = HostIdentity::from_seed(&[0x31; 32]).id();
        let pk = *device(0x32).public_key_bytes();
        let mut known = KnownHosts::default();
        known.pin(host, "Front desk", pk, 1000);
        known.save(&known_hosts_file(&paths)).unwrap();
        Store::new(&paths).name(host, Some(pk), "Studio").unwrap();
        let like = words.pairing_sheet(&device(0x77), "Front desk", false);
        assert_eq!(like.looks_like.as_deref(), Some("Front desk"));
        let alias = words.pairing_sheet(&device(0x78), "Studio", false);
        assert_eq!(alias.looks_like.as_deref(), Some("Studio"));
        let calm = words.pairing_sheet(&device(0x79), "Kitchen", false);
        assert_eq!(calm.looks_like, None);
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

    /// F-3: a pairing request withdrawn or timed out while its derivation
    /// waits on the pacer derives nothing: the queued run is dropped with
    /// the answer, and the pacer starts no run for it.
    #[tokio::test]
    async fn a_withdrawn_request_derives_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let (_, words) = home(tmp.path());
        let words = Arc::new(words);
        let popups = popups();
        let consent = consent(&popups, Arc::clone(&words));
        // The pacer has just run: the next unsaved key waits its second.
        let _ = words.pacer().derive(&[0x90; 32], Role::Device);
        assert_eq!(words.pacer().runs(), 1);
        // The FSM's popup timeout, standing in for a withdrawal: the answer
        // is dropped while its derivation is still queued.
        let peer = peer(0x7a, "Kitchen");
        let timed_out = tokio::time::timeout(
            Duration::from_millis(200),
            consent.pairing(&peer, "123 456"),
        )
        .await;
        assert!(timed_out.is_err(), "answered before its derivation ran");
        // Well past the pacer's second: the queued run saw the flag and
        // skipped the derivation.
        tokio::time::sleep(Duration::from_millis(1300)).await;
        assert_eq!(words.pacer().runs(), 1, "a withdrawn request was derived");
        assert!(popups.shared().read(|m| m.popups.is_empty()));
        // The same key asked again, and not withdrawn: derived and shown.
        let asking = consent.pairing(&peer, "123 456");
        tokio::pin!(asking);
        let popup = tokio::select! {
            _ = &mut asking => panic!("answered early"),
            popup = shown(&popups) => popup,
        };
        assert_eq!(words.pacer().runs(), 2);
        assert!(popups.answer_pairing(popup.id, PairDecision::Reject));
        assert_eq!(asking.await, PairDecision::Reject);
    }

    /// F-4: a file of saved entries that cannot be read makes the alarm say
    /// it could not compare, never compare silently against fewer entries:
    /// the pairing sheet takes only the typed code, and the connect field
    /// asks for the second click.
    #[tokio::test]
    async fn an_unreadable_saved_file_is_could_not_compare() {
        for damaged in ["address-book", "trusted-devices", "known-hosts"] {
            let tmp = tempfile::tempdir().unwrap();
            let (paths, words) = home(tmp.path());
            assert!(words.saved_set().1, "{damaged}: an intact home");
            let file = match damaged {
                "address-book" => Store::new(&paths).book_path().to_path_buf(),
                "trusted-devices" => paths.trusted_devices_file(),
                _ => known_hosts_file(&paths),
            };
            std::fs::create_dir_all(file.parent().unwrap()).unwrap();
            std::fs::write(&file, "this is [not toml").unwrap();
            let (saved, complete) = words.saved_set();
            assert!(!complete, "{damaged}: read as complete");
            // This computer's own entries stay in the set.
            assert!(saved.len() >= 2, "{damaged}");
            let seen = words.pairing_sheet(&device(0x7b), "Kitchen", false);
            assert_eq!(seen.looks_like, None, "{damaged}");
            assert!(seen.unchecked && seen.typed_only(), "{damaged}: {seen:?}");
            // A match among the entries that could be read still names it.
            let like = words.pairing_sheet(&device(0x78), "linux pc", false);
            assert_eq!(like.looks_like.as_deref(), Some("Linux PC"), "{damaged}");
            assert!(!like.unchecked, "{damaged}");
            let id = HostIdentity::from_seed(&[0x6c; 32]).id();
            assert_eq!(
                words.connect_check(&id),
                Some(Lookalike::Unchecked),
                "{damaged}"
            );
        }
        // Through the window's consent: no click accept on such a sheet.
        let tmp = tempfile::tempdir().unwrap();
        let (paths, words) = home(tmp.path());
        std::fs::write(paths.trusted_devices_file(), "[[devices]\n").unwrap();
        let popups = popups();
        let consent = consent(&popups, Arc::new(words));
        let peer = peer(0x7c, "Kitchen");
        let asking = consent.pairing(&peer, "123 456");
        tokio::pin!(asking);
        let popup = tokio::select! {
            _ = &mut asking => panic!("answered early"),
            popup = shown(&popups) => popup,
        };
        let seen = popups.shared().read(|m| m.recognition[&popup.id].clone());
        assert!(seen.unchecked);
        assert!(popups.answer_pairing(popup.id, PairDecision::Accept { label: None }));
        assert_eq!(
            asking.await,
            PairDecision::Reject,
            "a click paired an unchecked sheet"
        );
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

    /// R-3c and the default log: under the default filter (the log a user
    /// gets without asking for more), over a first connection — the pairing
    /// sheet with the alarm and the typed code, then the session sheet
    /// answered View only — no line holds a saved name, a declared name, a
    /// pinned label, an ID or its prefix, a fingerprint or any single device
    /// word of the keys involved, and the log still says what happened.
    #[tokio::test]
    async fn the_default_log_names_nobody_over_a_first_connection() {
        use tracing_subscriber::layer::SubscriberExt as _;

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
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let writer = Capture(Arc::clone(&buffer));
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::EnvFilter::new(
                tornect_core::telemetry::DEFAULT_FILTER,
            ))
            .with(
                tracing_subscriber::fmt::layer()
                    .fmt_fields(tornect_core::telemetry::redacting_fields())
                    .with_ansi(false)
                    .with_writer(move || writer.clone()),
            );
        // This test's thread only: the runtime is single-threaded.
        let _default = tracing::subscriber::set_default(subscriber);

        let tmp = tempfile::tempdir().unwrap();
        let (_, words) = home(tmp.path());
        let words = Arc::new(words);
        let popups = popups();
        let consent = Arc::new(consent(&popups, Arc::clone(&words)));
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
                    panic!("a pairing sheet first");
                };
                assert!(popups.answer_pairing_code(popup.id, &sas, Some("Front desk".to_owned())));
                loop {
                    let next = shown(&popups).await;
                    if next.id != popup.id {
                        assert!(matches!(next.kind, PopupKind::Session { .. }));
                        return popups.answer_session(
                            next.id,
                            tornect_signal::pairing::SessionDecision::AllowOnceViewOnly,
                        );
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
        };
        let mut cdeps =
            ClientDeps::headless(Arc::new(KnownHostStore::ephemeral(Default::default())));
        cdeps.ui = Arc::new(ScriptedClientUi::new(true));
        let asking = DeviceIdentity::from_seed(&[0x77; 32]);
        let ccfg = ClientConfig::new(identity.id(), "Office PC");
        let outcome = connect(client_end, &ccfg, &asking, &cdeps, Intent::Session).await;
        assert!(answering.await.unwrap(), "both sheets were answered");
        assert!(
            matches!(outcome, Ok(ClientOutcome::Session(_))),
            "{outcome:?}"
        );
        drop(outcome);
        host.abort();

        let text = String::from_utf8(
            buffer
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
        )
        .unwrap();
        for said in ["device paired", "host paired", "session accepted"] {
            assert!(text.contains(said), "\"{said}\" not in the log:\n{text}");
        }
        let mut secrets: Vec<String> = ["Front desk", "Office PC", "Linux PC", "Desk"]
            .map(str::to_owned)
            .to_vec();
        secrets.push(identity.id().short());
        secrets.push(asking.id().fingerprint());
        for key in [
            derive(asking.id().public_key_bytes(), Role::Device),
            derive(identity.id().public_key_bytes(), Role::Onion),
        ] {
            secrets.extend(key.words().get().map(str::to_owned));
        }
        for secret in secrets {
            assert!(
                !text.contains(&secret),
                "\"{secret}\" in the default log:\n{text}"
            );
        }
    }
}
