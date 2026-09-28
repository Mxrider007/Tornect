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
