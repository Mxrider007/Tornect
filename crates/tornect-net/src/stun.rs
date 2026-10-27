//! The STUN Binding codec of the server-reflexive candidate (design
//! `direct` §6.4, §5.3; decisions M1-81, M1-86; RFC 8489, with the RFC 5769
//! test vectors; docs/research/nat-traversal.md §2).
//!
//! ```text
//! request  (20 B): 00 01 | 00 00 | 21 12 A4 42 | txid[12]          (no attributes)
//! response       : 01 01 | len u16 | 21 12 A4 42 | txid[12] | attributes (TLV, 4-byte padded)
//! ```
//!
//! The request is the bare header: no SOFTWARE (it would name Tornect in
//! cleartext, decision M1-86) and no FINGERPRINT (replies are told apart by
//! byte 0, the cookie, the transaction ID and an exact source match). A
//! response is read by [`parse_response`], which takes nothing it does not
//! understand: a success response with an unknown comprehension-required
//! attribute is discarded (RFC 8489 §6.3.3), and so is anything malformed.
//! Tornect never answers STUN, so there is no response encoder here.
//!
//! [`partition`] splits the user's server list between the two roles by
//! operator (§5.3), so that one operator never sees both ends of a
//! session; the client that asks the servers is
//! [`gather`](crate::gather)'s.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::TornectRole;
use crate::addr::Redacted;
use crate::udp::{STUN_COOKIE, STUN_MAX_LEN, STUN_REQUEST_LEN};

/// The length of a STUN header, which is all a Binding request without
/// attributes is (RFC 8489 §5).
pub const HEADER_LEN: usize = STUN_REQUEST_LEN;

/// The length of a STUN transaction ID (96 bits).
pub const TXID_LEN: usize = 12;

/// A STUN transaction ID: 12 bytes from the OS's random source, one per
/// server asked (its retransmission reuses it, RFC 8489 §6.2.1).
pub type StunTxid = [u8; TXID_LEN];

/// The Binding request's message type (method `0x001`, class request).
pub const BINDING_REQUEST: u16 = 0x0001;

/// The Binding success response's message type.
pub const BINDING_SUCCESS: u16 = 0x0101;

/// The Binding error response's message type.
pub const BINDING_ERROR: u16 = 0x0111;

/// The attribute types the codec names (IANA "STUN Attributes" registry).
pub mod attr {
    /// MAPPED-ADDRESS (RFC 8489 §14.1): read only when no
    /// XOR-MAPPED-ADDRESS is present (RFC 3489 era servers).
    pub const MAPPED_ADDRESS: u16 = 0x0001;
    /// XOR-MAPPED-ADDRESS (RFC 8489 §14.2): the first one wins.
    pub const XOR_MAPPED_ADDRESS: u16 = 0x0020;
    /// Comprehension-required types that carry nothing the codec needs,
    /// skipped instead of discarding the response: the RFC 3489
    /// SOURCE-ADDRESS (`0x0004`) and CHANGED-ADDRESS (`0x0005`), USERNAME,
    /// MESSAGE-INTEGRITY (both RFC 5769 responses carry it), ERROR-CODE and
    /// MESSAGE-INTEGRITY-SHA256. None of them carries an address.
    pub const SKIPPED_REQUIRED: [u16; 6] = [0x0004, 0x0005, 0x0006, 0x0008, 0x0009, 0x001C];
    /// The first comprehension-optional type: this and every type above it
    /// (SOFTWARE `0x8022`, FINGERPRINT `0x8028`, RESPONSE-ORIGIN `0x802B`,
    /// OTHER-ADDRESS `0x802C`, …) is skipped without verification.
    pub const FIRST_OPTIONAL: u16 = 0x8000;
}

/// The port of an XOR-MAPPED-ADDRESS is XORed with the cookie's top half.
const PORT_MASK: u16 = 0x2112;

/// Address family codes of the (XOR-)MAPPED-ADDRESS value.
const FAMILY_V4: u8 = 0x01;
const FAMILY_V6: u8 = 0x02;

/// The value lengths of the two address families.
const VALUE_LEN_V4: usize = 8;
const VALUE_LEN_V6: usize = 20;

/// The Binding request this side sends (design §6.4): the 20-byte header,
/// no attributes.
#[must_use]
pub fn binding_request(txid: &StunTxid) -> [u8; HEADER_LEN] {
    let mut request = [0; HEADER_LEN];
    request[..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    // Bytes 2..4, the attributes' length, stay 0.
    request[4..8].copy_from_slice(&STUN_COOKIE);
    request[8..].copy_from_slice(txid);
    request
}

/// What a server answered (design §6.4).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum StunReply {
    /// A success response: the address the server saw this side's request
    /// come from.
    Mapped(SocketAddr),
    /// An error response: this server gives nothing, and it is not asked
    /// again in this session.
    ErrorResponse,
}

impl fmt::Debug for StunReply {
    /// The mapped address as its family and class only (decision M1-83).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mapped(addr) => f.debug_tuple("Mapped").field(&Redacted(addr)).finish(),
            Self::ErrorResponse => f.write_str("ErrorResponse"),
        }
    }
}

/// Reads a datagram as the response to the request whose transaction ID is
/// `txid`. `None` when it is not ours, malformed, or unacceptable (design
/// §6.4):
///
/// - it is 20 to 548 bytes, byte 0 is at most `0x03`, bytes 4..8 are the
///   magic cookie and bytes 8..20 are `txid`;
/// - the header's length is the rest of the datagram and a multiple of 4;
/// - its type is the Binding success (`0x0101`) or error (`0x0111`)
///   response: a request, an indication or another method is refused;
/// - its attributes fill the message exactly, each padded to 4 bytes; one
///   that overruns discards the response, and so does a (XOR-)MAPPED-ADDRESS
///   whose family is not IPv4 with a value of 8 bytes or IPv6 with 20;
/// - an error response is [`StunReply::ErrorResponse`] whatever else it
///   carries (RFC 8489 §6.3.4: the transaction failed);
/// - a success response is the first XOR-MAPPED-ADDRESS, else the first
///   MAPPED-ADDRESS; it is discarded when it carries neither, or when it
///   carries a comprehension-required attribute other than those two and
///   [`attr::SKIPPED_REQUIRED`] (RFC 8489 §6.3.3).
///
/// What the mapped address must be to become a candidate (global IPv4, from
/// the server asked, not one of this side's own) is the STUN client's rule,
/// not the codec's.
#[must_use]
pub fn parse_response(buf: &[u8], txid: &StunTxid) -> Option<StunReply> {
    if !(HEADER_LEN..=STUN_MAX_LEN).contains(&buf.len())
        || buf[0] > 0x03
        || buf[4..8] != STUN_COOKIE
        || buf[8..HEADER_LEN] != txid[..]
    {
        return None;
    }
    let length = usize::from(u16::from_be_bytes([buf[2], buf[3]]));
    if length != buf.len() - HEADER_LEN || length % 4 != 0 {
        return None;
    }
    let success = match u16::from_be_bytes([buf[0], buf[1]]) {
        BINDING_SUCCESS => true,
        BINDING_ERROR => false,
        _ => return None,
    };

    let mut xor_mapped = None;
    let mut mapped = None;
    let mut unknown_required = false;
    let mut at = HEADER_LEN;
    // `length` is a multiple of 4, and so is every padded attribute: at
    // each turn either nothing or at least one 4-byte attribute header is
    // left.
    while at < buf.len() {
        let kind = u16::from_be_bytes([buf[at], buf[at + 1]]);
        let len = usize::from(u16::from_be_bytes([buf[at + 2], buf[at + 3]]));
        let start = at + 4;
        let end = start + len.next_multiple_of(4);
        if end > buf.len() {
            return None;
        }
        let value = &buf[start..start + len];
        match kind {
            attr::XOR_MAPPED_ADDRESS => {
                let addr = decode_address(value, Some(txid))?;
                xor_mapped.get_or_insert(addr);
            }
            attr::MAPPED_ADDRESS => {
                let addr = decode_address(value, None)?;
                mapped.get_or_insert(addr);
            }
            k if k >= attr::FIRST_OPTIONAL || attr::SKIPPED_REQUIRED.contains(&k) => {}
            _ => unknown_required = true,
        }
        at = end;
    }

    if !success {
        return Some(StunReply::ErrorResponse);
    }
    if unknown_required {
        return None;
    }
    xor_mapped.or(mapped).map(StunReply::Mapped)
}

/// A (XOR-)MAPPED-ADDRESS value (RFC 8489 §14.1, §14.2): one reserved byte
/// (ignored), the family, the port, then 4 or 16 address bytes. With
/// `xor`, the port is XORed with `0x2112`, an IPv4 address with the cookie
/// and an IPv6 address with the cookie and then the transaction ID.
fn decode_address(value: &[u8], xor: Option<&StunTxid>) -> Option<SocketAddr> {
    let family = *value.get(1)?;
    let expected = match family {
        FAMILY_V4 => VALUE_LEN_V4,
        FAMILY_V6 => VALUE_LEN_V6,
        _ => return None,
    };
    if value.len() != expected {
        return None;
    }
    let mut port = u16::from_be_bytes([value[2], value[3]]);
    let mut bytes = [0_u8; 16];
    let raw = &value[4..];
    bytes[..raw.len()].copy_from_slice(raw);
    if let Some(txid) = xor {
        port ^= PORT_MASK;
        let mut mask = [0_u8; 16];
        mask[..4].copy_from_slice(&STUN_COOKIE);
        mask[4..].copy_from_slice(txid);
        for (b, m) in bytes.iter_mut().zip(mask) {
            *b ^= m;
        }
    }
    let ip = if family == FAMILY_V4 {
        IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
    } else {
        IpAddr::V6(Ipv6Addr::from(bytes))
    };
    Some(SocketAddr::new(ip, port))
}

/// The operators of the default list and of the servers users are likely to
/// add (design §5.3): a host whose name is one of these registrable domains
/// or below one belongs to that operator, whatever its other labels say
/// (`stun.l.google.com` and `stun1.l.google.com` are both Google's).
pub const STUN_OPERATORS: [(&str, &str); 4] = [
    ("cloudflare.com", "Cloudflare, Inc."),
    ("google.com", "Google LLC"),
    ("twilio.com", "Twilio Inc."),
    ("nextcloud.com", "Nextcloud GmbH"),
];

/// The operator of a `stun_servers` entry (`host:port`), as the partition
/// groups entries (design §5.3): the host lowercased, without its port,
/// brackets or final dot; then a [`STUN_OPERATORS`] domain it is or lies
/// below, else its last two DNS labels. An IP literal is its own operator:
/// nothing tells which network runs it.
#[must_use]
pub fn operator(entry: &str) -> String {
    let host = entry.rsplit_once(':').map_or(entry, |(host, _)| host);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.parse::<IpAddr>().is_ok() {
        return host;
    }
    for (domain, _) in STUN_OPERATORS {
        if host == domain || host.strip_suffix(domain).is_some_and(|s| s.ends_with('.')) {
            return domain.to_owned();
        }
    }
    let labels: Vec<&str> = host.rsplitn(3, '.').collect();
    match labels.as_slice() {
        [last, second, ..] => format!("{second}.{last}"),
        _ => host,
    }
}

/// This side's part of the `stun_servers` list (design §5.3): the entries
/// grouped by [`operator`], the groups in the order their operator first
/// appears; the viewer takes the groups at even places (0, 2, …) and the
/// host those at odd places, so no operator is in both parts, whatever the
/// list. A list of one operator is both sides' part. The entries keep their
/// order within a group, and an entry listed twice is kept once.
#[must_use]
pub fn partition(list: &[String], role: TornectRole) -> Vec<String> {
    let mut groups: Vec<(String, Vec<String>)> = Vec::new();
    for entry in list {
        let key = operator(entry);
        let at = match groups.iter().position(|(k, _)| *k == key) {
            Some(at) => at,
            None => {
                groups.push((key, Vec::new()));
                groups.len() - 1
            }
        };
        let group = &mut groups[at].1;
        if !group.contains(entry) {
            group.push(entry.clone());
        }
    }
    if groups.len() == 1 {
        return groups.remove(0).1;
    }
    let first = match role {
        TornectRole::Viewer => 0,
        TornectRole::Host => 1,
    };
    groups
        .into_iter()
        .skip(first)
        .step_by(2)
        .flat_map(|(_, entries)| entries)
        .collect()
}

#[cfg(test)]
mod tests;
