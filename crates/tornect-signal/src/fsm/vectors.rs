//! The fixed inputs behind the M1 golden vectors (decision M1-10,
//! `docs/notes/m1-golden-vector.md`), shared by the `golden` tests, the
//! committed fuzz seeds (`fuzz/seeds/envelope/`) and the F1 fuzz target, so
//! that one definition keeps the three in sync.
//!
//! Nothing here is secret: the seeds are constants, and the identities they
//! produce exist only in tests.

use std::sync::Arc;

use tornect_core::{DeviceIdentity, HostIdentity, TornectId};

use super::ScriptedRandom;
use super::client::ClientConfig;
use super::host::HostConfig;
use crate::messages::{Caps, Resolution};

/// Host onion identity seed.
pub const HOST_SEED: [u8; 32] = [0x11; 32];
/// Client device identity seed.
pub const CLIENT_SEED: [u8; 32] = [0x22; 32];
/// Seed of the host's *device* identity (`PAIR_ACCEPT.host_device_pk`,
/// `SESSION_ACCEPT.quic_spki`).
pub const HOST_DEVICE_SEED: [u8; 32] = [0xB0; 32];
/// `HELLO.client_nonce`, and (its first 8 bytes) the client's `PING` nonce.
pub const CLIENT_NONCE: [u8; 32] = [0x33; 32];
/// `HELLO_ACK.host_nonce`.
pub const HOST_NONCE: [u8; 32] = [0x44; 32];
/// The attended `session_token`.
pub const SESSION_TOKEN: [u8; 32] = [0x55; 32];
/// The client's declared name.
pub const CLIENT_NAME: &str = "golden-client";
/// The host's name (`PAIR_ACCEPT.host_name`).
pub const HOST_NAME: &str = "golden-host";

/// The host onion identity.
#[must_use]
pub fn host_identity() -> HostIdentity {
    HostIdentity::from_seed(&HOST_SEED)
}

/// The client device identity.
#[must_use]
pub fn client_identity() -> DeviceIdentity {
    DeviceIdentity::from_seed(&CLIENT_SEED)
}

/// The host's device public key (a valid Ed25519 point, unlike a byte fill).
#[must_use]
pub fn host_device_pk() -> [u8; 32] {
    DeviceIdentity::from_seed(&HOST_DEVICE_SEED)
        .verifying_key()
        .to_bytes()
}

/// The host configuration of the vectors: `feats = ["ua1"]`, caps
/// `["h264", "av1"]`, 2560×1440, HDR, two monitors.
#[must_use]
pub fn host_config() -> HostConfig {
    let mut cfg = HostConfig::new(HOST_NAME, host_device_pk());
    cfg.feats = vec!["ua1".into()];
    cfg.caps = Caps {
        codecs: vec!["h264".into(), "av1".into()],
        max_res: Resolution {
            width: 2560,
            height: 1440,
        },
        hdr: true,
        monitors: 2,
    };
    cfg
}

/// The client configuration of the vectors: `feats = ["ua1"]`, caps
/// `["h264"]`, 1920×1080, no HDR, one monitor.
#[must_use]
pub fn client_config(host: TornectId) -> ClientConfig {
    let mut cfg = ClientConfig::new(host, CLIENT_NAME);
    cfg.feats = vec!["ua1".into()];
    cfg.caps = Caps {
        codecs: vec!["h264".into()],
        max_res: Resolution {
            width: 1920,
            height: 1080,
        },
        hdr: false,
        monitors: 1,
    };
    cfg
}

/// The host's scripted randomness: `HOST_NONCE`, then `SESSION_TOKEN`.
#[must_use]
pub fn host_random() -> Arc<ScriptedRandom> {
    Arc::new(ScriptedRandom::new(vec![
        HOST_NONCE.to_vec(),
        SESSION_TOKEN.to_vec(),
    ]))
}

/// The client's scripted randomness: `CLIENT_NONCE` for every fill.
#[must_use]
pub fn client_random() -> Arc<ScriptedRandom> {
    Arc::new(ScriptedRandom::new(vec![CLIENT_NONCE.to_vec()]))
}
