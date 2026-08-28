//! Local, append-only audit log of consent and session events
//! (`docs/PLAN.md` §B.6: "all session starts/ends logged locally").
//!
//! One JSON object per line so it is greppable and survives partial writes.

use std::io::{BufRead as _, Write as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::error::{CoreError, Result};
use crate::id::DeviceId;

/// What happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionEvent {
    /// A device asked to pair.
    PairRequested,
    /// The user accepted a pairing (SAS confirmed).
    PairAccepted,
    /// The user rejected a pairing.
    PairRejected,
    /// A paired device asked for a session.
    SessionRequested,
    /// A session began streaming.
    SessionStarted,
    /// A session ended (either side, or error).
    SessionEnded,
    /// The user (or policy) denied a session.
    SessionDenied,
    /// An unattended-access authentication attempt failed.
    UnattendedAuthFailed,
    /// An unattended-access authentication succeeded.
    UnattendedAuthSucceeded,
    /// A device or the host entered lockout after repeated failures.
    UnattendedLockout,
    /// The host user hit the panic key.
    PanicDisconnect,
    /// The host identity was rotated; all pairings invalidated.
    HostIdRotated,
}

/// What the client may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionMode {
    /// View and control.
    Control,
    /// View only; input is dropped host-side.
    ViewOnly,
}

/// How media flowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    /// Direct hole-punched QUIC.
    Direct,
    /// Same LAN.
    Lan,
    /// Relayed through the Tor circuit.
    TorRelay,
}

/// One log line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRecord {
    /// RFC 3339 UTC timestamp.
    pub ts: String,
    /// Event kind.
    pub event: SessionEvent,
    /// Session identifier (hex), if the event belongs to a session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// The remote device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_device: Option<DeviceId>,
    /// The remote device's self-declared name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_name: Option<String>,
    /// Session mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<SessionMode>,
    /// Whether this was an unattended (popup-less) session.
    #[serde(default)]
    pub unattended: bool,
    /// Media transport, once known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<TransportKind>,
    /// Free-text detail (reason, error, duration).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl SessionRecord {
    /// A record for `event` stamped with the current UTC time.
    #[must_use]
    pub fn now(event: SessionEvent) -> Self {
        let ts = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned());
        Self {
            ts,
            event,
            session_id: None,
            peer_device: None,
            peer_name: None,
            mode: None,
            unattended: false,
            transport: None,
            detail: None,
        }
    }

    /// Attach the peer device.
    #[must_use]
    pub fn peer(mut self, device: DeviceId, name: impl Into<String>) -> Self {
        self.peer_device = Some(device);
        self.peer_name = Some(name.into());
        self
    }

    /// Attach the session id.
    #[must_use]
    pub fn session(mut self, id: impl Into<String>) -> Self {
        self.session_id = Some(id.into());
        self
    }

    /// Attach the mode.
    #[must_use]
    pub fn mode(mut self, mode: SessionMode) -> Self {
        self.mode = Some(mode);
        self
    }

    /// Mark as unattended.
    #[must_use]
    pub fn unattended(mut self, yes: bool) -> Self {
        self.unattended = yes;
        self
    }

    /// Attach the transport.
    #[must_use]
    pub fn transport(mut self, t: TransportKind) -> Self {
        self.transport = Some(t);
        self
    }

    /// Attach free-text detail.
    #[must_use]
    pub fn detail(mut self, d: impl Into<String>) -> Self {
        self.detail = Some(d.into());
        self
    }
}

/// Append-only writer/reader for `sessions.log`.
#[derive(Debug, Clone)]
pub struct SessionLog {
    path: PathBuf,
}

impl SessionLog {
    /// Use the log at `path` (created on first append).
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one record and flush.
    pub fn append(&self, record: &SessionRecord) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            crate::keystore::create_private_dir(parent)?;
        }
        let mut line = serde_json::to_string(record)
            .map_err(|e| CoreError::SessionLog(format!("serialize: {e}")))?;
        line.push('\n');

        let mut opts = fs_err::OpenOptions::new();
        opts.append(true).create(true);
        #[cfg(unix)]
        {
            use fs_err::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut f = opts.open(&self.path)?;
        f.write_all(line.as_bytes())?;
        f.flush()?;
        Ok(())
    }

    /// Read every well-formed record; malformed lines are skipped with a warning.
    pub fn read_all(&self) -> Result<Vec<SessionRecord>> {
        let file = match fs_err::File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut out = Vec::new();
        for (n, line) in std::io::BufReader::new(file).lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<SessionRecord>(&line) {
                Ok(r) => out.push(r),
                Err(e) => {
                    tracing::warn!(line = n + 1, error = %e, "skipping malformed sessions.log line")
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let log = SessionLog::new(dir.path().join("logs").join("sessions.log"));
        assert!(log.read_all().unwrap().is_empty());

        let dev = DeviceId::from_bytes([1u8; 32]);
        let r1 = SessionRecord::now(SessionEvent::PairAccepted).peer(dev, "Laptop");
        let r2 = SessionRecord::now(SessionEvent::SessionStarted)
            .peer(dev, "Laptop")
            .session("abcd")
            .mode(SessionMode::Control)
            .unattended(true)
            .transport(TransportKind::Direct);
        log.append(&r1).unwrap();
        log.append(&r2).unwrap();

        // a corrupt line must not poison the reader
        std::fs::OpenOptions::new()
            .append(true)
            .open(log.path())
            .unwrap()
            .write_all(b"{not json\n")
            .unwrap();

        let all = log.read_all().unwrap();
        assert_eq!(all, vec![r1, r2.clone()]);
        assert!(all[1].unattended);
        assert!(all[0].ts.ends_with('Z'));
        assert_eq!(r2.transport, Some(TransportKind::Direct));
    }
}
