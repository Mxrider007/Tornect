//! The punch probe (design `direct` §6.2; decision M1-80): a 40-byte
//! datagram authenticated with a key only the two peers of one session
//! hold, sent both ways to validate a path before any QUIC byte crosses it.
//!
//! ```text
//! off len field
//!  0   1  lead   random in 0x04..=0x3F: bit 0x40 clear, so never a QUIC
//!                packet while the QUIC bit is not greased; >= 0x04, so never
//!                STUN (0x00..=0x03, RFC 9443)
//!  1  12  txid   request: 12 random bytes, fresh per send; response: the
//!                request's txid
//! 13   1  flags  bit 0: a response; bit 1: sent by the host; bits 2..7 random
//! 14  10  pad    random
//! 24  16  tag    HMAC-SHA256(k_probe, bytes[0..24])[0..16]
//!
//! k_probe = HKDF-SHA256(ikm = session_token, salt = none,
//!                       info = "tornect/v1/punch-probe-key")
//! ```
//!
//! No byte is constant besides the two flag bits and the lead range: the
//! tag authenticates everything, and a change of format goes through the
//! successor of the `dir1` feature token, never a version field here. A
//! request and its response have the same size, so answering one never
//! amplifies. The residual fingerprint is the fixed size and the timing.
//!
//! What a receiver accepts beyond [`ProbeKey::decode`] (an outstanding
//! txid sent to exactly the source, each request answered once, admitted
//! sources only, rate limits) is the checklist's (`crate::checklist`).

use std::fmt;
use std::ops::Range;

use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::TornectRole;
use crate::udp::{PROBE_LEADS, PROBE_LEN};

/// The HKDF-SHA256 `info` that derives the probe key from the session
/// token (salt none).
pub const PROBE_KEY_INFO: &[u8] = b"tornect/v1/punch-probe-key";

/// The length of a probe's transaction id.
pub const TXID_LEN: usize = 12;

/// The length of a probe's tag (HMAC-SHA256 truncated).
pub const TAG_LEN: usize = 16;

/// The random bytes one probe takes besides its txid: the lead, the six
/// random flag bits and the padding.
pub const NOISE_LEN: usize = 12;

/// A probe's transaction id.
pub type Txid = [u8; TXID_LEN];

const TXID: Range<usize> = 1..13;
const FLAGS: usize = 13;
const PAD: Range<usize> = 14..24;
const AUTHENTICATED: Range<usize> = 0..24;
const TAG: Range<usize> = 24..40;

/// Flag bit 0: the probe answers a request.
const FLAG_RESPONSE: u8 = 0x01;
/// Flag bit 1: the host sent the probe.
const FLAG_HOST: u8 = 0x02;
/// The flag bits that carry meaning; the others are random.
const FLAG_BITS: u8 = FLAG_RESPONSE | FLAG_HOST;

/// How many lead values there are (`0x04..=0x3F`).
const LEAD_SPAN: u8 = 60;

const _: () = assert!(TAG.end == PROBE_LEN && TXID.end == FLAGS && PAD.end == TAG.start);
const _: () = assert!(*PROBE_LEADS.start() == 0x04 && *PROBE_LEADS.end() == 0x04 + LEAD_SPAN - 1);

/// An authenticated probe, as [`ProbeKey::decode`] read it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Probe {
    /// It answers a request (it carries that request's txid).
    pub response: bool,
    /// The side that sent it.
    pub sender: TornectRole,
    /// Its transaction id.
    pub txid: Txid,
}

impl fmt::Debug for Probe {
    /// The kind and the sender; the txid is left out (it is random, but a
    /// log line has no use for it).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Probe")
            .field("response", &self.response)
            .field("sender", &self.sender)
            .finish_non_exhaustive()
    }
}

/// Why [`ProbeKey::decode`] refused a datagram; counted, never logged with
/// the datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProbeDrop {
    /// Not 40 bytes, or a lead byte outside `0x04..=0x3F`.
    Shape,
    /// The tag does not verify under this session's key.
    Tag,
    /// It claims to come from the receiver's own role: a reflection of one
    /// of the receiver's own probes.
    OwnRole,
}

/// The probe key of one session: `HKDF-SHA256(session_token, info =
/// PROBE_KEY_INFO)`, wiped on drop. It never leaves this type: the only
/// operations are sealing and checking probes.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ProbeKey([u8; 32]);

impl ProbeKey {
    /// The probe key of the session whose Tor-borne token is
    /// `session_token`.
    #[must_use]
    pub fn derive(session_token: &[u8; 32]) -> Self {
        let mut key = Self([0; 32]);
        hkdf::Hkdf::<Sha256>::new(None, session_token)
            .expand(PROBE_KEY_INFO, &mut key.0)
            .unwrap_or_else(|_| unreachable!("32 bytes is a valid HKDF-SHA256 output length"));
        key
    }

    /// The full HMAC of the authenticated part; the tag is its first
    /// [`TAG_LEN`] bytes.
    fn mac(&self, authenticated: &[u8]) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0)
            .unwrap_or_else(|_| unreachable!("HMAC-SHA256 takes a key of any length"));
        mac.update(authenticated);
        mac.finalize().into_bytes().into()
    }

    /// A probe with the given fields. `noise` supplies the random bytes:
    /// `noise[0]` picks the lead (`0x04 + noise[0] % 60`), `noise[1]` the
    /// six random flag bits, `noise[2..]` the padding. [`request`] and
    /// [`response`] fill it from the OS; tests and fuzz targets pass their
    /// own.
    ///
    /// [`request`]: Self::request
    /// [`response`]: Self::response
    #[must_use]
    pub fn seal(
        &self,
        response: bool,
        sender: TornectRole,
        txid: &Txid,
        noise: &[u8; NOISE_LEN],
    ) -> [u8; PROBE_LEN] {
        let mut bytes = [0; PROBE_LEN];
        bytes[0] = PROBE_LEADS.start() + noise[0] % LEAD_SPAN;
        bytes[TXID].copy_from_slice(txid);
        let mut flags = noise[1] & !FLAG_BITS;
        if response {
            flags |= FLAG_RESPONSE;
        }
        if sender == TornectRole::Host {
            flags |= FLAG_HOST;
        }
        bytes[FLAGS] = flags;
        bytes[PAD].copy_from_slice(&noise[2..]);
        let mac = self.mac(&bytes[AUTHENTICATED]);
        bytes[TAG].copy_from_slice(&mac[..TAG_LEN]);
        bytes
    }

    /// A fresh request from `sender`: a random txid and random noise from
    /// the OS. `None` when the OS has no randomness to give; the caller
    /// sends nothing.
    #[must_use]
    pub fn request(&self, sender: TornectRole) -> Option<(Txid, [u8; PROBE_LEN])> {
        let mut random = [0; TXID_LEN + NOISE_LEN];
        getrandom::fill(&mut random).ok()?;
        let mut txid = [0; TXID_LEN];
        txid.copy_from_slice(&random[..TXID_LEN]);
        let mut noise = [0; NOISE_LEN];
        noise.copy_from_slice(&random[TXID_LEN..]);
        Some((txid, self.seal(false, sender, &txid, &noise)))
    }

    /// The response from `sender` to the request whose txid is `txid`, with
    /// fresh noise from the OS; `None` when the OS has no randomness.
    #[must_use]
    pub fn response(&self, sender: TornectRole, txid: &Txid) -> Option<[u8; PROBE_LEN]> {
        let mut noise = [0; NOISE_LEN];
        getrandom::fill(&mut noise).ok()?;
        Some(self.seal(true, sender, txid, &noise))
    }

    /// Reads a datagram that `receiver` got: its shape, then its tag
    /// (compared in constant time), then its sender, which must be the
    /// other role.
    ///
    /// # Errors
    ///
    /// The first check that fails, in that order.
    pub fn decode(&self, receiver: TornectRole, bytes: &[u8]) -> Result<Probe, ProbeDrop> {
        if bytes.len() != PROBE_LEN || !PROBE_LEADS.contains(&bytes[0]) {
            return Err(ProbeDrop::Shape);
        }
        let mac = self.mac(&bytes[AUTHENTICATED]);
        if !bool::from(mac[..TAG_LEN].ct_eq(&bytes[TAG])) {
            return Err(ProbeDrop::Tag);
        }
        let flags = bytes[FLAGS];
        let sender = if flags & FLAG_HOST == 0 {
            TornectRole::Viewer
        } else {
            TornectRole::Host
        };
        if sender == receiver {
            return Err(ProbeDrop::OwnRole);
        }
        let mut txid = [0; TXID_LEN];
        txid.copy_from_slice(&bytes[TXID]);
        Ok(Probe {
            response: flags & FLAG_RESPONSE != 0,
            sender,
            txid,
        })
    }
}

impl fmt::Debug for ProbeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProbeKey(..)")
    }
}

#[cfg(test)]
mod tests;
