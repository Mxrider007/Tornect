//! The ledger of router port mappings (design `direct` §7.4 "Ledger",
//! decision M1-81): a record of every mapping this process asked a router
//! for, written **before** the request, so that a process that ends without
//! releasing its mappings (a crash, a kill, a power cut) leaves enough for
//! the next start to remove them ([`super::RealMapper::sweep`]).
//!
//! **Layout** ([`tornect_core::Paths::router_ports_dir`]): one directory,
//! `0700`; per process that has asked a router for anything, a lock file
//! `<owner>.lock` it holds (an OS file lock, `File::try_lock`) for as long as
//! its ledger lives, and the list `<owner>.cbor` (`0600`, replaced
//! atomically on each change). `<owner>` is 16 random hex digits. The lock
//! is what tells a live owner from a dead one: the OS drops it when the
//! process ends, however it ends, so a list whose lock can be taken is a
//! leftover (the lock file is locked before it takes its name, so a running
//! owner's never shows unlocked), and one whose lock is held belongs to a
//! running process (a GUI and a `tornect connect` on one `TORNECT_HOME`),
//! whose mappings a sweep never touches. The design's single
//! `router-ports.cbor` would let one process's start-up sweep remove the
//! live mappings of another.
//!
//! **The list** is a CBOR array of entries (`LedgerEntry` on the wire):
//!
//! ```text
//! Entry = { 0: via uint (0 PCP, 1 NAT-PMP, 2 UPnP), 1: gateway bstr(4),
//!           2: client bstr(4), 3: internal_port uint, ? 4: external_port uint,
//!           ? 5: pcp_nonce [3 * uint], 6: created uint (Unix seconds) }
//! ```
//!
//! It holds the router's LAN address, this computer's LAN address and port
//! numbers (design §5.5): never a public address, never a peer's. Reading is
//! bounded ([`MAX_LEDGER_BYTES`], [`MAX_LEDGER_ENTRIES`]) and an entry that
//! does not decode, or names an unknown protocol, is dropped alone.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read as _};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use minicbor::{Decode, Decoder, Encode, Encoder};

use super::MapVia;
use crate::addr::RedactedIp;

/// How old a leftover entry may be and still be removed from the router
/// (design §7.4: "entries older than 24 h are dropped unswept").
pub const LEDGER_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// The most entries one list holds, and the most a sweep reads from one
/// list. A process adds one per mapping it asks for and removes it after
/// the release, so a live list rarely holds more than two; when full, a new
/// entry evicts the oldest one that backs no mapping held now.
pub const MAX_LEDGER_ENTRIES: usize = 64;

/// The largest list a sweep reads; a larger file is not a ledger this
/// code wrote, and is removed unread.
pub const MAX_LEDGER_BYTES: u64 = 64 * 1024;

/// The most dead owners' lists one sweep handles.
pub const MAX_LEDGER_OWNERS: usize = 32;

/// One mapping in the ledger. Its `Debug` prints the protocol and address
/// classes only (decision M1-83).
#[derive(Clone, PartialEq, Eq)]
pub struct LedgerEntry {
    /// The protocol the request used.
    pub via: MapVia,
    /// The router asked (the default gateway).
    pub gateway: Ipv4Addr,
    /// This computer's address toward it (the IPv4 route source).
    pub client: Ipv4Addr,
    /// The session socket's port.
    pub internal_port: u16,
    /// The router's external port, written only once the router granted
    /// it: a UPnP leftover is removed by it, and a port the router refused
    /// may be another computer's. PCP and NAT-PMP delete by nonce and
    /// internal port and leave it out.
    pub external_port: Option<u16>,
    /// The PCP nonce, chosen by Tornect so that a deletion can name the
    /// mapping after a crash (RFC 6887 §11.1).
    pub pcp_nonce: Option<[u32; 3]>,
    /// When the mapping was last asked for (Unix seconds): its request, then
    /// each renewal.
    pub created: u64,
}

impl fmt::Debug for LedgerEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LedgerEntry")
            .field("via", &self.via)
            .field("gateway", &RedactedIp(IpAddr::V4(self.gateway)))
            .field("client", &RedactedIp(IpAddr::V4(self.client)))
            .field("external_port_known", &self.external_port.is_some())
            .field("pcp_nonce", &self.pcp_nonce.is_some())
            .finish_non_exhaustive()
    }
}

/// The wire form of an entry: integers and bytes only, so that one entry
/// with an unknown protocol never makes the whole list unreadable.
#[derive(Encode, Decode)]
#[cbor(map)]
struct WireEntry {
    #[n(0)]
    via: u32,
    #[n(1)]
    #[cbor(with = "minicbor::bytes")]
    gateway: [u8; 4],
    #[n(2)]
    #[cbor(with = "minicbor::bytes")]
    client: [u8; 4],
    #[n(3)]
    internal_port: u16,
    #[n(4)]
    external_port: Option<u16>,
    #[n(5)]
    pcp_nonce: Option<[u32; 3]>,
    #[n(6)]
    created: u64,
}

fn via_code(via: MapVia) -> u32 {
    match via {
        MapVia::Pcp => 0,
        MapVia::NatPmp => 1,
        MapVia::Upnp => 2,
    }
}

fn via_of(code: u32) -> Option<MapVia> {
    match code {
        0 => Some(MapVia::Pcp),
        1 => Some(MapVia::NatPmp),
        2 => Some(MapVia::Upnp),
        _ => None,
    }
}

impl LedgerEntry {
    fn wire(&self) -> WireEntry {
        WireEntry {
            via: via_code(self.via),
            gateway: self.gateway.octets(),
            client: self.client.octets(),
            internal_port: self.internal_port,
            external_port: self.external_port,
            pcp_nonce: self.pcp_nonce,
            created: self.created,
        }
    }

    /// The entry a wire entry stands for, if it is one this code can act
    /// on: a known protocol, a non-zero internal port, and a nonce for PCP.
    fn from_wire(w: WireEntry) -> Option<Self> {
        let via = via_of(w.via)?;
        if w.internal_port == 0 || (via == MapVia::Pcp && w.pcp_nonce.is_none()) {
            return None;
        }
        Some(Self {
            via,
            gateway: Ipv4Addr::from(w.gateway),
            client: Ipv4Addr::from(w.client),
            internal_port: w.internal_port,
            external_port: w.external_port.filter(|p| *p != 0),
            pcp_nonce: w.pcp_nonce,
            created: w.created,
        })
    }
}

/// The bytes of a list.
#[must_use]
pub fn encode_list(entries: &[LedgerEntry]) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    // Writing into a `Vec` cannot fail.
    let _ = e.array(entries.len() as u64);
    for entry in entries {
        let _ = e.encode(entry.wire());
    }
    e.into_writer()
}

/// What a list holds: the entries this code can act on, and how many it
/// dropped (malformed, an unknown protocol, beyond [`MAX_LEDGER_ENTRIES`]).
/// Bytes that are not a CBOR array at all give no entry and one drop.
#[must_use]
pub fn decode_list(bytes: &[u8]) -> (Vec<LedgerEntry>, usize) {
    let mut d = Decoder::new(bytes);
    let Ok(Some(len)) = d.array() else {
        return (Vec::new(), 1);
    };
    let mut entries = Vec::new();
    let mut dropped = 0_usize;
    for _ in 0..len {
        if entries.len() == MAX_LEDGER_ENTRIES {
            dropped += 1;
            continue;
        }
        let at = d.position();
        match d.decode::<WireEntry>() {
            Ok(w) => match LedgerEntry::from_wire(w) {
                Some(entry) => entries.push(entry),
                None => dropped += 1,
            },
            Err(_) => {
                dropped += 1;
                d.set_position(at);
                if d.skip().is_err() {
                    // The rest is unreadable: count it as one more drop.
                    break;
                }
            }
        }
    }
    (entries, dropped)
}

/// The current Unix time in seconds (0 before 1970).
#[must_use]
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The handle of one entry in this process's ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EntryId(u64);

struct Slot {
    id: EntryId,
    entry: LedgerEntry,
    /// A mapping held now stands behind it; never persisted.
    live: bool,
}

struct State {
    dir: PathBuf,
    owner: String,
    lock: Option<File>,
    slots: Vec<Slot>,
    next: u64,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Whether `name` is a ledger file (`<16 hex>.lock` or `.cbor`), and whose.
fn owner_of(name: &str) -> Option<&str> {
    let (owner, ext) = name.split_once('.')?;
    let ours = owner.len() == 16
        && owner
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && (ext == "lock" || ext == "cbor");
    ours.then_some(owner)
}

fn random_owner() -> String {
    let mut bytes = [0_u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        // No randomness: a name from the clock and the process; owners
        // only need to differ between the processes of one machine.
        let mix = u64::from(std::process::id()) << 32 ^ unix_now();
        bytes = mix.to_le_bytes();
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn io_other<E>(_: E) -> io::Error {
    io::Error::from(io::ErrorKind::Other)
}

fn open_lock(path: &Path, create: bool) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(create).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Reads a list, bounded: a missing file is an empty list, a file larger
/// than [`MAX_LEDGER_BYTES`] one drop.
fn read_list(path: &Path) -> (Vec<LedgerEntry>, usize) {
    let Ok(file) = File::open(path) else {
        return (Vec::new(), 0);
    };
    let mut bytes = Vec::new();
    if file
        .take(MAX_LEDGER_BYTES + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() as u64 > MAX_LEDGER_BYTES
    {
        return (Vec::new(), 1);
    }
    if bytes.is_empty() {
        return (Vec::new(), 0);
    }
    decode_list(&bytes)
}

impl State {
    fn data_path(&self) -> PathBuf {
        self.dir.join(format!("{}.cbor", self.owner))
    }

    fn lock_path(&self) -> PathBuf {
        self.dir.join(format!("{}.lock", self.owner))
    }

    /// Creates the directory and takes this owner's lock, once. The lock
    /// file is created and locked under a name no sweep reads
    /// (`<owner>.new`), then renamed into place: a sweep that lists the
    /// directory meanwhile never finds an unlocked `<owner>.lock` of a
    /// running process, which it would take for a dead one and remove.
    fn own(&mut self) -> io::Result<()> {
        if self.lock.is_some() {
            return Ok(());
        }
        tornect_core::keystore::create_private_dir(&self.dir).map_err(io_other)?;
        let fresh = self.dir.join(format!("{}.new", self.owner));
        let file = open_lock(&fresh, true)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            Err(std::fs::TryLockError::Error(e)) => return Err(e),
        }
        if let Err(e) = std::fs::rename(&fresh, self.lock_path()) {
            let _ = std::fs::remove_file(&fresh);
            return Err(e);
        }
        self.lock = Some(file);
        Ok(())
    }

    fn persist(&mut self) -> io::Result<()> {
        self.own()?;
        let entries: Vec<LedgerEntry> = self.slots.iter().map(|s| s.entry.clone()).collect();
        tornect_core::keystore::write_private_file_atomic(&self.data_path(), &encode_list(&entries))
            .map_err(io_other)
    }

    fn slot(&mut self, id: EntryId) -> Option<&mut Slot> {
        self.slots.iter_mut().find(|s| s.id == id)
    }
}

impl Drop for State {
    /// An empty ledger leaves nothing behind; a ledger that still lists
    /// mappings keeps its list for the next start, and its lock goes with
    /// the handle.
    fn drop(&mut self) {
        let Some(lock) = self.lock.take() else {
            return;
        };
        if self.slots.is_empty() {
            let _ = std::fs::remove_file(self.data_path());
            let _ = std::fs::remove_file(self.lock_path());
        }
        drop(lock);
    }
}

/// This process's ledger. Clones share it. Its methods do file I/O and
/// block: async callers run them on the blocking pool.
#[derive(Clone)]
pub struct MappingLedger {
    state: Arc<Mutex<State>>,
}

impl fmt::Debug for MappingLedger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = lock(&self.state);
        f.debug_struct("MappingLedger")
            .field("entries", &state.slots.len())
            .field("owned", &state.lock.is_some())
            .finish_non_exhaustive()
    }
}

impl MappingLedger {
    /// A ledger in `dir` ([`tornect_core::Paths::router_ports_dir`]) under a
    /// fresh owner name. Nothing is created until the first entry.
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                dir: dir.into(),
                owner: random_owner(),
                lock: None,
                slots: Vec::new(),
                next: 0,
            })),
        }
    }

    /// The directory.
    #[must_use]
    pub fn dir(&self) -> PathBuf {
        lock(&self.state).dir.clone()
    }

    /// Records `entry` and writes the list, before the request it stands
    /// for is sent. A full list evicts its oldest entry that backs no
    /// mapping held now; a list full of held mappings refuses.
    ///
    /// # Errors
    ///
    /// The directory, the lock or the list could not be written, or the
    /// list is full: the request must not be sent, since a crash would
    /// leave its mapping with no record.
    pub fn add(&self, entry: LedgerEntry) -> io::Result<EntryId> {
        let mut state = lock(&self.state);
        if state.slots.len() >= MAX_LEDGER_ENTRIES {
            let oldest = state
                .slots
                .iter()
                .enumerate()
                .filter(|(_, s)| !s.live)
                .min_by_key(|(_, s)| s.entry.created)
                .map(|(i, _)| i);
            match oldest {
                Some(i) => {
                    state.slots.remove(i);
                }
                None => return Err(io::ErrorKind::StorageFull.into()),
            }
        }
        let id = EntryId(state.next);
        state.next += 1;
        state.slots.push(Slot {
            id,
            entry,
            live: false,
        });
        if let Err(e) = state.persist() {
            state.slots.retain(|s| s.id != id);
            return Err(e);
        }
        Ok(id)
    }

    /// Changes an entry (its protocol, its external port, its time) and
    /// writes the list.
    ///
    /// # Errors
    ///
    /// The list could not be written; the entry is changed in memory.
    pub fn update(&self, id: EntryId, change: impl FnOnce(&mut LedgerEntry)) -> io::Result<()> {
        let mut state = lock(&self.state);
        let Some(slot) = state.slot(id) else {
            return Ok(());
        };
        change(&mut slot.entry);
        state.persist()
    }

    /// Marks whether a mapping held now stands behind the entry (memory
    /// only).
    pub fn set_live(&self, id: EntryId, live: bool) {
        if let Some(slot) = lock(&self.state).slot(id) {
            slot.live = live;
        }
    }

    /// Removes an entry, after its mapping was removed from the router or
    /// was never made, and writes the list.
    ///
    /// # Errors
    ///
    /// The list could not be written; the entry is gone from memory, and a
    /// later write drops it from the file.
    pub fn remove(&self, id: EntryId) -> io::Result<()> {
        let mut state = lock(&self.state);
        let before = state.slots.len();
        state.slots.retain(|s| s.id != id);
        if state.slots.len() == before {
            return Ok(());
        }
        state.persist()
    }

    /// Lets go of the lock and keeps the list, as a process that dies does:
    /// a crash, for this crate's tests (a leaked mapping keeps the ledger
    /// alive in memory, where a real crash would not).
    #[cfg(test)]
    pub(crate) fn abandon(&self) {
        lock(&self.state).lock = None;
    }

    /// The entries listed now, oldest first.
    #[must_use]
    pub fn entries(&self) -> Vec<LedgerEntry> {
        lock(&self.state)
            .slots
            .iter()
            .map(|s| s.entry.clone())
            .collect()
    }

    /// The lists of dead owners in this ledger's directory, each locked for
    /// the caller, at most [`MAX_LEDGER_OWNERS`]; never this ledger's own,
    /// nor one whose owner runs.
    #[must_use]
    pub fn take_leftovers(&self) -> Vec<Leftover> {
        let (dir, own) = {
            let state = lock(&self.state);
            (state.dir.clone(), state.owner.clone())
        };
        owners(&dir)
            .into_iter()
            .filter(|o| *o != own)
            .filter_map(|owner| Leftover::take(&dir, owner))
            .take(MAX_LEDGER_OWNERS)
            .collect()
    }

    /// How many entries dead owners left in `dir`, without taking or
    /// changing anything (`doctor`'s "router ports left from an earlier
    /// run").
    #[must_use]
    pub fn leftovers(dir: &Path) -> usize {
        owners(dir)
            .into_iter()
            .take(MAX_LEDGER_OWNERS)
            .map(|owner| {
                if let Ok(file) = File::open(dir.join(format!("{owner}.lock")))
                    && file.try_lock().is_err()
                {
                    return 0;
                }
                read_list(&dir.join(format!("{owner}.cbor"))).0.len()
            })
            .sum()
    }
}

/// The owners named in `dir`, sorted.
fn owners(dir: &Path) -> Vec<String> {
    let Ok(read) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut owners: Vec<String> = read
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().to_str().and_then(owner_of).map(str::to_owned))
        .collect();
    owners.sort_unstable();
    owners.dedup();
    owners
}

/// A dead owner's list, locked by the sweep that took it.
pub struct Leftover {
    dir: PathBuf,
    owner: String,
    lock: File,
    /// What it lists.
    pub entries: Vec<LedgerEntry>,
    /// What it held that could not be acted on.
    pub unreadable: usize,
}

impl fmt::Debug for Leftover {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Leftover")
            .field("entries", &self.entries.len())
            .field("unreadable", &self.unreadable)
            .finish_non_exhaustive()
    }
}

impl Leftover {
    fn take(dir: &Path, owner: String) -> Option<Self> {
        let lock = open_lock(&dir.join(format!("{owner}.lock")), true).ok()?;
        lock.try_lock().ok()?;
        let (entries, unreadable) = read_list(&dir.join(format!("{owner}.cbor")));
        Some(Self {
            dir: dir.to_owned(),
            owner,
            lock,
            entries,
            unreadable,
        })
    }

    /// Ends the sweep of this list: with nothing `kept`, both files go;
    /// otherwise the list is rewritten with `kept`, for the next start.
    ///
    /// # Errors
    ///
    /// The files could not be removed or written.
    pub fn finish(self, kept: &[LedgerEntry]) -> io::Result<()> {
        let data = self.dir.join(format!("{}.cbor", self.owner));
        let lock_path = self.dir.join(format!("{}.lock", self.owner));
        let result = if kept.is_empty() {
            match std::fs::remove_file(&data) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e),
            }
            .and_then(|()| match std::fs::remove_file(&lock_path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e),
            })
        } else {
            tornect_core::keystore::write_private_file_atomic(&data, &encode_list(kept))
                .map_err(io_other)
        };
        drop(self.lock);
        result
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn pcp_entry() -> LedgerEntry {
        LedgerEntry {
            via: MapVia::Pcp,
            gateway: Ipv4Addr::new(192, 168, 1, 1),
            client: Ipv4Addr::new(192, 168, 1, 20),
            internal_port: 50_000,
            external_port: Some(50_000),
            pcp_nonce: Some([1, 2, 3]),
            created: 1_700_000_000,
        }
    }

    fn natpmp_entry(created: u64) -> LedgerEntry {
        LedgerEntry {
            via: MapVia::NatPmp,
            gateway: Ipv4Addr::new(10, 0, 0, 1),
            client: Ipv4Addr::new(10, 0, 0, 7),
            internal_port: 41_000,
            external_port: None,
            pcp_nonce: None,
            created,
        }
    }

    /// The wire form, byte for byte: a one-entry list of a PCP mapping.
    #[test]
    fn golden_bytes_of_a_list() {
        let bytes = encode_list(&[pcp_entry()]);
        assert_eq!(
            bytes,
            [
                0x81, 0xA7, 0x00, 0x00, 0x01, 0x44, 0xC0, 0xA8, 0x01, 0x01, 0x02, 0x44, 0xC0, 0xA8,
                0x01, 0x14, 0x03, 0x19, 0xC3, 0x50, 0x04, 0x19, 0xC3, 0x50, 0x05, 0x83, 0x01, 0x02,
                0x03, 0x06, 0x1A, 0x65, 0x53, 0xF1, 0x00,
            ]
        );
        assert_eq!(decode_list(&bytes), (vec![pcp_entry()], 0));
    }

    /// Absent fields are left out of the map, and come back absent.
    #[test]
    fn absent_fields_are_left_out() {
        let entry = natpmp_entry(5);
        let bytes = encode_list(std::slice::from_ref(&entry));
        assert_eq!(&bytes[..2], [0x81, 0xA5]);
        assert_eq!(decode_list(&bytes), (vec![entry], 0));
        assert_eq!(decode_list(&encode_list(&[])), (Vec::new(), 0));
    }

    /// One bad entry is dropped alone; bytes that are not a list give
    /// nothing; truncation and wrong types never panic.
    #[test]
    fn malformed_lists_drop_what_they_must() {
        // Not an array.
        assert_eq!(decode_list(&[0xA0]), (Vec::new(), 1));
        assert_eq!(decode_list(&[]), (Vec::new(), 1));
        // An unknown protocol, then a good entry.
        let mut bytes = vec![0x82];
        let mut unknown = encode_list(&[pcp_entry()]);
        unknown[3] = 0x07;
        bytes.extend_from_slice(&unknown[1..]);
        bytes.extend_from_slice(&encode_list(&[natpmp_entry(9)])[1..]);
        assert_eq!(decode_list(&bytes), (vec![natpmp_entry(9)], 1));
        // A wrong type for the protocol (a text string), then a good entry.
        let mut bytes = vec![0x82, 0xA1, 0x00, 0x61, b'x'];
        bytes.extend_from_slice(&encode_list(&[natpmp_entry(9)])[1..]);
        assert_eq!(decode_list(&bytes), (vec![natpmp_entry(9)], 1));
        // PCP without a nonce, internal port 0: not acted on.
        let mut no_nonce = pcp_entry();
        no_nonce.pcp_nonce = None;
        let mut port_zero = natpmp_entry(1);
        port_zero.internal_port = 0;
        let (entries, dropped) = decode_list(&encode_list(&[no_nonce, port_zero]));
        assert!(entries.is_empty());
        assert_eq!(dropped, 2);
        // Every truncation of a good list.
        let good = encode_list(&[pcp_entry(), natpmp_entry(3)]);
        for cut in 0..good.len() {
            let (entries, _) = decode_list(&good[..cut]);
            assert!(entries.len() <= 1, "cut at {cut}");
        }
    }

    /// A list longer than [`MAX_LEDGER_ENTRIES`] is read up to it.
    #[test]
    fn a_long_list_is_read_up_to_its_bound() {
        let many: Vec<LedgerEntry> = (0..MAX_LEDGER_ENTRIES as u64 + 3)
            .map(natpmp_entry)
            .collect();
        let (entries, dropped) = decode_list(&encode_list(&many));
        assert_eq!(entries.len(), MAX_LEDGER_ENTRIES);
        assert_eq!(dropped, 3);
    }

    fn arb_entry() -> impl Strategy<Value = LedgerEntry> {
        (
            0_u8..3,
            any::<[u8; 4]>(),
            any::<[u8; 4]>(),
            1_u16..,
            proptest::option::of(1_u16..),
            any::<[u32; 3]>(),
            any::<u64>(),
        )
            .prop_map(|(via, gw, client, port, ext, nonce, created)| {
                let via = via_of(u32::from(via)).expect("a known protocol");
                LedgerEntry {
                    via,
                    gateway: Ipv4Addr::from(gw),
                    client: Ipv4Addr::from(client),
                    internal_port: port,
                    external_port: ext,
                    pcp_nonce: (via == MapVia::Pcp).then_some(nonce),
                    created,
                }
            })
    }

    proptest! {
        #[test]
        fn lists_round_trip(entries in proptest::collection::vec(arb_entry(), 0..8)) {
            prop_assert_eq!(decode_list(&encode_list(&entries)), (entries, 0));
        }

        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let (entries, _) = decode_list(&bytes);
            prop_assert!(entries.len() <= MAX_LEDGER_ENTRIES);
            for entry in entries {
                prop_assert!(entry.internal_port != 0);
                prop_assert!(entry.via != MapVia::Pcp || entry.pcp_nonce.is_some());
            }
        }
    }

    fn files(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .map(|r| {
                r.filter_map(Result::ok)
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    /// The entry is on disk when `add` returns, the list follows each
    /// change, and a ledger that ends empty leaves nothing behind.
    #[test]
    fn the_list_is_written_before_add_returns_and_cleared_after() {
        let home = tempfile::tempdir().expect("a temporary directory");
        let dir = home.path().join("router-ports");
        let ledger = MappingLedger::new(&dir);
        assert!(!dir.exists(), "nothing is created before the first entry");
        let id = ledger.add(pcp_entry()).expect("written");
        let names = files(&dir);
        assert_eq!(names.len(), 2, "{names:?}");
        let data = dir.join(names.iter().find(|n| n.ends_with(".cbor")).unwrap());
        assert_eq!(read_list(&data), (vec![pcp_entry()], 0));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&dir), 0o700);
            assert_eq!(mode(&data), 0o600);
        }
        ledger
            .update(id, |e| e.external_port = Some(50_001))
            .expect("rewritten");
        assert_eq!(read_list(&data).0[0].external_port, Some(50_001));
        ledger.remove(id).expect("rewritten");
        assert_eq!(read_list(&data), (Vec::new(), 0));
        drop(ledger);
        assert!(files(&dir).is_empty(), "{:?}", files(&dir));
    }

    /// A full list evicts its oldest entry that backs no mapping held now,
    /// and refuses when every entry backs one.
    #[test]
    fn a_full_list_evicts_the_oldest_unheld_entry() {
        let home = tempfile::tempdir().expect("a temporary directory");
        let ledger = MappingLedger::new(home.path());
        let ids: Vec<EntryId> = (0..MAX_LEDGER_ENTRIES as u64)
            .map(|i| ledger.add(natpmp_entry(100 + i)).expect("written"))
            .collect();
        for id in &ids[..2] {
            ledger.set_live(*id, true);
        }
        ledger.add(natpmp_entry(1_000)).expect("evicts one");
        let created: Vec<u64> = ledger.entries().iter().map(|e| e.created).collect();
        assert_eq!(created.len(), MAX_LEDGER_ENTRIES);
        assert!(
            created.contains(&100) && created.contains(&101),
            "held entries stay"
        );
        assert!(!created.contains(&102), "the oldest unheld one goes");
        for id in &ids {
            ledger.set_live(*id, true);
        }
        let all_live = MappingLedger::new(home.path().join("other"));
        for i in 0..MAX_LEDGER_ENTRIES as u64 {
            let id = all_live.add(natpmp_entry(i)).expect("written");
            all_live.set_live(id, true);
        }
        assert_eq!(
            all_live.add(natpmp_entry(7)).expect_err("full").kind(),
            io::ErrorKind::StorageFull
        );
    }

    /// A ledger that ends with entries (a crash) leaves its list; a later
    /// ledger in the same directory takes it, but never one whose owner
    /// still runs, nor its own.
    #[test]
    fn leftovers_are_the_lists_of_dead_owners_only() {
        let home = tempfile::tempdir().expect("a temporary directory");
        let dir = home.path().to_owned();
        let crashed = MappingLedger::new(&dir);
        crashed.add(pcp_entry()).expect("written");
        let running = MappingLedger::new(&dir);
        running.add(natpmp_entry(4)).expect("written");
        assert_eq!(MappingLedger::leftovers(&dir), 0, "both owners run");
        drop(crashed);
        assert_eq!(MappingLedger::leftovers(&dir), 1);
        assert!(running.take_leftovers().len() == 1);
        // The first sweep took and released it untouched; a second one
        // finishes it.
        let next = MappingLedger::new(&dir);
        let mut leftovers = next.take_leftovers();
        assert_eq!(leftovers.len(), 1, "the running owner's list is not taken");
        let left = leftovers.pop().unwrap();
        assert_eq!(left.entries, vec![pcp_entry()]);
        assert_eq!(left.unreadable, 0);
        left.finish(&[]).expect("removed");
        assert_eq!(MappingLedger::leftovers(&dir), 0);
        assert_eq!(files(&dir).len(), 2, "the running owner's files stay");
        assert!(next.take_leftovers().is_empty());
        assert_eq!(running.entries(), vec![natpmp_entry(4)]);
    }

    /// A kept leftover is written back for the next start; an oversized or
    /// garbage list is unreadable, and stray files are not ledgers.
    #[test]
    fn kept_and_unreadable_leftovers() {
        let home = tempfile::tempdir().expect("a temporary directory");
        let dir = home.path().to_owned();
        let crashed = MappingLedger::new(&dir);
        crashed.add(pcp_entry()).expect("written");
        crashed.add(natpmp_entry(8)).expect("written");
        drop(crashed);
        let first = MappingLedger::new(&dir).take_leftovers();
        assert_eq!(first.len(), 1);
        let left = first.into_iter().next().unwrap();
        left.finish(&[natpmp_entry(8)]).expect("rewritten");
        let again = MappingLedger::new(&dir).take_leftovers();
        assert_eq!(again[0].entries, vec![natpmp_entry(8)]);
        drop(again);

        std::fs::write(dir.join("00000000000000aa.cbor"), [0xFF; 9]).unwrap();
        std::fs::write(
            dir.join("00000000000000bb.cbor"),
            vec![0_u8; MAX_LEDGER_BYTES as usize + 1],
        )
        .unwrap();
        std::fs::write(dir.join("notes.txt"), b"not a ledger").unwrap();
        std::fs::write(dir.join("00000000000000CC.cbor"), b"upper case").unwrap();
        let taken = MappingLedger::new(&dir).take_leftovers();
        assert_eq!(taken.len(), 3, "{taken:?}");
        let unreadable: usize = taken.iter().map(|l| l.unreadable).sum();
        assert_eq!(unreadable, 2);
        for left in taken {
            left.finish(&[]).expect("removed");
        }
        assert_eq!(files(&dir), ["00000000000000CC.cbor", "notes.txt"]);
    }

    /// Decision M1-83: neither an entry nor a ledger prints an address or
    /// a port.
    #[test]
    fn no_debug_prints_an_address_or_a_port() {
        let home = tempfile::tempdir().expect("a temporary directory");
        let ledger = MappingLedger::new(home.path());
        ledger.add(pcp_entry()).expect("written");
        let text = format!("{:?} {:#?} {ledger:?}", pcp_entry(), pcp_entry());
        for piece in ["192", "168", "50000", "50_000", "1700000000"] {
            assert!(!text.contains(piece), "\"{piece}\" in {text}");
        }
        assert!(text.contains("v4 private"), "{text}");
    }
}
