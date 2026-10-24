//! [`ReadinessSnapshot`] / [`Probe`] (`docs/PLAN.md` §B.8.7.1 ⑥, §B.8.14): one probe
//! per readiness row, an all-`Unknown` M1 stub (the `tornect-platform` probes fill it
//! from M6), the post-F2 `HOST_NOT_READY` gate rule and the IPC form — a CBOR map keyed
//! by field **name** whose decoder ignores unknown keys, so M6 may add probes without an
//! IPC schema bump.

use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use minicbor::decode::Decoder;
use minicbor::encode::{Encoder, Write};

/// How often a host probes its readiness again, after the probe at its start
/// (§B.8.7.1 ⑥: macOS's periodic re-consent, Wayland's grant lost).
pub const REPROBE_EVERY: Duration = Duration::from_secs(10 * 60);

/// One readiness row.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Probe {
    /// Green.
    Ok,
    /// Yellow: badge only.
    Warn(String),
    /// Red: badge, and — on the gating rows — `HOST_NOT_READY`.
    Fail(String),
    /// Not probed (M1): never blocks, badge only.
    #[default]
    Unknown,
}

impl Probe {
    fn kind(&self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::Warn(_) => 1,
            Self::Fail(_) => 2,
            Self::Unknown => 3,
        }
    }

    fn message(&self) -> Option<&str> {
        match self {
            Self::Warn(m) | Self::Fail(m) => Some(m),
            _ => None,
        }
    }

    /// Whether this row raises the badge.
    #[must_use]
    pub fn raises_badge(&self) -> bool {
        !matches!(self, Self::Ok)
    }
}

impl<C> minicbor::Encode<C> for Probe {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        _: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.array(2)?.u8(self.kind())?;
        match self.message() {
            Some(m) => e.str(m)?,
            None => e.null()?,
        };
        Ok(())
    }
}

impl<'b, C> minicbor::Decode<'b, C> for Probe {
    fn decode(d: &mut Decoder<'b>, _: &mut C) -> Result<Self, minicbor::decode::Error> {
        let p = d.position();
        let n = d.array()?;
        if n != Some(2) {
            return Err(minicbor::decode::Error::message("probe must be a 2-array").at(p));
        }
        let kind = d.u8()?;
        let msg: Option<String> = if d.datatype()? == minicbor::data::Type::Null {
            d.skip()?;
            None
        } else {
            let s = d.str()?;
            Some(s.chars().take(MAX_PROBE_MESSAGE).collect())
        };
        Ok(match kind {
            0 => Self::Ok,
            1 => Self::Warn(msg.unwrap_or_default()),
            2 => Self::Fail(msg.unwrap_or_default()),
            _ => Self::Unknown,
        })
    }
}

/// Probe messages are truncated to this many characters on decode.
pub const MAX_PROBE_MESSAGE: usize = 256;

/// The readiness rows of §B.8.7.1 ⑥.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReadinessSnapshot {
    /// Capture permission / restore token.
    pub capture: Probe,
    /// Input permission / restore token.
    pub input: Probe,
    /// Autostart registered.
    pub autostart: Probe,
    /// Auto-login state (never configured by Tornect).
    pub auto_login: Probe,
    /// Keystore persistent and unlockable at autostart (canary).
    pub keystore: Probe,
    /// Empty OS account password detected.
    pub os_password: Probe,
    /// Idle-lock policy.
    pub idle_lock: Probe,
    /// Current lock state.
    pub lock_state: Probe,
    /// Console ownership.
    pub console_owner: Probe,
    /// Tor self-connect.
    pub tor_self_connect: Probe,
    /// Panic key bound.
    pub panic_key: Probe,
    /// Indicator + tray row.
    pub consent_indicator: Probe,
    /// The administrator helper registered (r7, Windows, while an admin grant
    /// exists).
    pub admin_helper: Probe,
    /// `sessions.log` as the host's start-up verifier found it (§B.8.13): a
    /// warning without a stored head, a failure ("log modified or truncated at
    /// line N") for a broken chain. Badge only, never `HOST_NOT_READY`.
    pub session_log: Probe,
}

/// Field names in wire order (also the CBOR map keys).
pub const FIELD_NAMES: [&str; 14] = [
    "capture",
    "input",
    "autostart",
    "auto_login",
    "keystore",
    "os_password",
    "idle_lock",
    "lock_state",
    "console_owner",
    "tor_self_connect",
    "panic_key",
    "consent_indicator",
    "admin_helper",
    "session_log",
];

/// What each row is called where people read it (§B.8.7.1 ⑥, §B.8.7.4), by
/// field name.
#[must_use]
pub fn row_title(field: &str) -> &'static str {
    match field {
        "capture" => "Screen capture permission",
        "input" => "Input permission",
        "autostart" => "Start at sign-in",
        "auto_login" => "Automatic sign-in",
        "keystore" => "Keystore persistent and unlockable at start",
        "os_password" => "Account password not empty",
        "idle_lock" => "Idle lock",
        "lock_state" => "Lock state",
        "console_owner" => "Console owner",
        "tor_self_connect" => "Tor self-connect",
        "panic_key" => "Panic key",
        "consent_indicator" => "Indicator shown",
        "admin_helper" => "Administrator helper registered",
        "session_log" => "Session log intact",
        _ => "Unknown row",
    }
}

impl ReadinessSnapshot {
    /// The M1 stub: every row `Unknown` (never blocks, badge only).
    #[must_use]
    pub fn unknown() -> Self {
        Self::default()
    }

    /// The rows in wire order.
    #[must_use]
    pub fn fields(&self) -> [(&'static str, &Probe); 14] {
        [
            ("capture", &self.capture),
            ("input", &self.input),
            ("autostart", &self.autostart),
            ("auto_login", &self.auto_login),
            ("keystore", &self.keystore),
            ("os_password", &self.os_password),
            ("idle_lock", &self.idle_lock),
            ("lock_state", &self.lock_state),
            ("console_owner", &self.console_owner),
            ("tor_self_connect", &self.tor_self_connect),
            ("panic_key", &self.panic_key),
            ("consent_indicator", &self.consent_indicator),
            ("admin_helper", &self.admin_helper),
            ("session_log", &self.session_log),
        ]
    }

    fn field_mut(&mut self, name: &str) -> Option<&mut Probe> {
        Some(match name {
            "capture" => &mut self.capture,
            "input" => &mut self.input,
            "autostart" => &mut self.autostart,
            "auto_login" => &mut self.auto_login,
            "keystore" => &mut self.keystore,
            "os_password" => &mut self.os_password,
            "idle_lock" => &mut self.idle_lock,
            "lock_state" => &mut self.lock_state,
            "console_owner" => &mut self.console_owner,
            "tor_self_connect" => &mut self.tor_self_connect,
            "panic_key" => &mut self.panic_key,
            "consent_indicator" => &mut self.consent_indicator,
            "admin_helper" => &mut self.admin_helper,
            "session_log" => &mut self.session_log,
            _ => return None,
        })
    }

    /// The post-F2 gate rule (§B.8.14): `Unknown` never blocks; `Fail` on `capture` /
    /// `input` / `lock_state` / `console_owner` ⇒ `HOST_NOT_READY` with cause 1 / 2 / 3 /
    /// 4; every other row raises the badge only.
    #[must_use]
    pub fn host_not_ready_cause(&self) -> Option<u8> {
        [
            (&self.capture, 1u8),
            (&self.input, 2),
            (&self.lock_state, 3),
            (&self.console_owner, 4),
        ]
        .into_iter()
        .find(|(p, _)| matches!(p, Probe::Fail(_)))
        .map(|(_, c)| c)
    }

    /// Whether any row raises the sticky badge.
    #[must_use]
    pub fn badge(&self) -> bool {
        self.fields().iter().any(|(_, p)| p.raises_badge())
    }
}

impl<C> minicbor::Encode<C> for ReadinessSnapshot {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.map(FIELD_NAMES.len() as u64)?;
        for (name, probe) in self.fields() {
            e.str(name)?;
            probe.encode(e, ctx)?;
        }
        Ok(())
    }
}

impl<'b, C> minicbor::Decode<'b, C> for ReadinessSnapshot {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        let mut out = Self::default();
        let n = d.map()?;
        let mut seen = 0u64;
        loop {
            match n {
                Some(n) if seen >= n => break,
                None if d.datatype()? == minicbor::data::Type::Break => {
                    d.skip()?;
                    break;
                }
                _ => {}
            }
            seen += 1;
            let key = d.str()?;
            match out.field_mut(key) {
                Some(slot) => *slot = Probe::decode(d, ctx)?,
                None => d.skip()?,
            }
        }
        Ok(out)
    }
}

/// The row "Session log intact" from the start-up verifier's answer
/// ([`GrantStore::verify_log`](super::store::GrantStore::verify_log), §B.8.13)
/// over a store in `status`. A broken chain fails ("log modified or truncated
/// at line N", the file named when the break is inside one); a log that could
/// not be read warns. A chain whose links hold is fine where no store keeps a
/// head (an attended-only host); a loaded store without a stored head warns;
/// a store that exists but could not be read warns too, since only the links
/// were checked then, not the tags or the end.
#[must_use]
pub fn session_log_row(
    verdict: &Result<crate::session_log::ChainReport, super::store::StoreError>,
    status: &super::store::StoreStatus,
) -> Probe {
    use super::store::StoreStatus;
    use crate::session_log::ChainStatus;
    match verdict {
        Ok(report) => match (&report.status, status) {
            (ChainStatus::Broken { file, line, reason }, _) if file.is_empty() => Probe::Fail(
                format!("log modified or truncated at line {line}: {reason}"),
            ),
            (ChainStatus::Broken { file, line, reason }, _) => Probe::Fail(format!(
                "log modified or truncated at line {line} of {file}: {reason}"
            )),
            (_, StoreStatus::FailedClosed(_)) => Probe::Warn(
                "the unattended store could not be read, so only the log's links were \
                 checked, not its tags or its end"
                    .to_owned(),
            ),
            (ChainStatus::MissingHead, StoreStatus::Loaded) => Probe::Warn(
                "the log's links hold, but no stored head was there to check its end against"
                    .to_owned(),
            ),
            (ChainStatus::Valid | ChainStatus::MissingHead, _) => Probe::Ok,
        },
        Err(e) => Probe::Warn(format!("the log could not be checked: {e}")),
    }
}

/// A host's readiness as last probed (at its start and every
/// [`REPROBE_EVERY`]), shared by the gate, which answers `HOST_NOT_READY` from
/// it, and the control channel.
#[derive(Debug, Clone, Default)]
pub struct SharedReadiness(Arc<RwLock<ReadinessSnapshot>>);

impl SharedReadiness {
    /// Start at `snapshot`.
    #[must_use]
    pub fn new(snapshot: ReadinessSnapshot) -> Self {
        Self(Arc::new(RwLock::new(snapshot)))
    }

    /// The rows as last probed.
    #[must_use]
    pub fn get(&self) -> ReadinessSnapshot {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The rows of a new probe.
    pub fn set(&self, snapshot: ReadinessSnapshot) {
        *self.0.write().unwrap_or_else(PoisonError::into_inner) = snapshot;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_is_all_unknown_and_never_blocks() {
        let s = ReadinessSnapshot::unknown();
        assert!(s.fields().iter().all(|(_, p)| **p == Probe::Unknown));
        assert_eq!(s.host_not_ready_cause(), None);
        assert!(s.badge());
    }

    #[test]
    fn gate_rule_causes_in_order() {
        let mut s = ReadinessSnapshot::unknown();
        s.autostart = Probe::Fail("no".into());
        assert_eq!(s.host_not_ready_cause(), None, "non-gating rows badge only");
        s.console_owner = Probe::Fail("other user".into());
        assert_eq!(s.host_not_ready_cause(), Some(4));
        s.lock_state = Probe::Fail("locked".into());
        assert_eq!(s.host_not_ready_cause(), Some(3));
        s.input = Probe::Warn("meh".into());
        assert_eq!(s.host_not_ready_cause(), Some(3));
        s.input = Probe::Fail("no".into());
        assert_eq!(s.host_not_ready_cause(), Some(2));
        s.capture = Probe::Fail("no".into());
        assert_eq!(s.host_not_ready_cause(), Some(1));
        let mut ok = ReadinessSnapshot::unknown();
        for (name, _) in ok.clone().fields() {
            *ok.field_mut(name).unwrap() = Probe::Ok;
        }
        assert!(!ok.badge());
    }

    #[test]
    fn cbor_is_keyed_by_field_name_and_ignores_unknown_keys() {
        let mut s = ReadinessSnapshot::unknown();
        s.capture = Probe::Ok;
        s.input = Probe::Fail("portal denied".into());
        s.keystore = Probe::Warn("file keystore".into());
        let bytes = minicbor::to_vec(&s).unwrap();
        assert!(
            bytes.windows(7).any(|w| w == b"capture"),
            "map keys are the field names"
        );
        let back: ReadinessSnapshot = minicbor::decode(&bytes).unwrap();
        assert_eq!(back, s);

        // a future probe and an unknown kind are tolerated
        let mut e = Encoder::new(Vec::new());
        e.map(3)
            .unwrap()
            .str("future_probe")
            .unwrap()
            .array(2)
            .unwrap()
            .u8(9)
            .unwrap()
            .null()
            .unwrap()
            .str("capture")
            .unwrap()
            .array(2)
            .unwrap()
            .u8(7)
            .unwrap()
            .str("??")
            .unwrap()
            .str("extra")
            .unwrap()
            .u64(5)
            .unwrap();
        let back: ReadinessSnapshot = minicbor::decode(&e.into_writer()).unwrap();
        assert_eq!(back.capture, Probe::Unknown);
        assert_eq!(back.input, Probe::Unknown);
        // a message is bounded on decode
        let long = Probe::Fail("x".repeat(1000));
        let bytes = minicbor::to_vec(&long).unwrap();
        let back: Probe = minicbor::decode(&bytes).unwrap();
        assert_eq!(back, Probe::Fail("x".repeat(MAX_PROBE_MESSAGE)));
    }

    /// B13: the start-up verifier's verdict is the row "Session log intact",
    /// one more named key (a decoder of the thirteen rows ignores it), badge
    /// only: a broken chain names the line, never `HOST_NOT_READY`.
    #[test]
    fn the_session_log_row_says_where_the_log_broke() {
        use super::super::codec::StoreLoadError;
        use super::super::store::StoreStatus;
        use crate::session_log::{ChainReport, ChainStatus};
        let (loaded, none) = (StoreStatus::Loaded, StoreStatus::AttendedOnly);
        let unread = StoreStatus::FailedClosed(StoreLoadError::BadTag);
        let report = |status| ChainReport {
            status,
            lines: 9,
            last_hash: None,
            tagged_beyond_head: 0,
            previous_epoch_lines: 0,
            torn_lines: 0,
        };
        assert_eq!(
            session_log_row(&Ok(report(ChainStatus::Valid)), &loaded),
            Probe::Ok
        );
        assert!(matches!(
            session_log_row(&Ok(report(ChainStatus::MissingHead)), &loaded),
            Probe::Warn(_)
        ));
        assert_eq!(
            session_log_row(&Ok(report(ChainStatus::MissingHead)), &none),
            Probe::Ok,
            "an attended-only host keeps no head"
        );
        // A store that could not be read gave no head, no epoch and no key: the
        // links alone were checked, which is said, whatever they came to.
        for status in [ChainStatus::Valid, ChainStatus::MissingHead] {
            match session_log_row(&Ok(report(status)), &unread) {
                Probe::Warn(why) => assert!(why.contains("only the log's links"), "{why}"),
                other => panic!("{other:?}"),
            }
        }
        let broken = ChainStatus::Broken {
            file: "sessions.log".into(),
            line: 7,
            reason: "prev link does not match the previous line".into(),
        };
        for status in [&none, &loaded, &unread] {
            assert_eq!(
                session_log_row(&Ok(report(broken.clone())), status),
                Probe::Fail(
                    "log modified or truncated at line 7 of sessions.log: prev link does not \
                     match the previous line"
                        .into()
                ),
                "a broken link fails, read store or not: {status:?}"
            );
        }
        let cut = ChainStatus::Broken {
            file: String::new(),
            line: 9,
            reason: "stored head matches no line (truncated log)".into(),
        };
        assert_eq!(
            session_log_row(&Ok(report(cut)), &loaded),
            Probe::Fail(
                "log modified or truncated at line 9: stored head matches no line (truncated log)"
                    .into()
            )
        );
        assert!(matches!(
            session_log_row(
                &Err(super::super::store::StoreError::Invalid("x".into())),
                &loaded
            ),
            Probe::Warn(_)
        ));

        let mut s = ReadinessSnapshot::unknown();
        s.session_log = Probe::Fail("log modified or truncated at line 7".into());
        assert_eq!(s.host_not_ready_cause(), None, "badge only");
        assert!(s.badge());
        let bytes = minicbor::to_vec(&s).unwrap();
        assert!(bytes.windows(11).any(|w| w == b"session_log"));
        let back: ReadinessSnapshot = minicbor::decode(&bytes).unwrap();
        assert_eq!(back, s);
        assert_eq!(row_title("session_log"), "Session log intact");
        assert_eq!(FIELD_NAMES.last(), Some(&"session_log"));
        let names: Vec<&str> = s.fields().iter().map(|(n, _)| *n).collect();
        assert_eq!(names, FIELD_NAMES);
    }

    /// The administrator helper's row (r7) travels as one more named key, which
    /// a decoder of the twelve rows ignores; this one reads a map without it as
    /// `Unknown` there. A probe shared with the gate is read as last set.
    #[test]
    fn the_admin_helper_row_is_one_more_named_key() {
        let mut s = ReadinessSnapshot::unknown();
        s.admin_helper = Probe::Fail("not registered".into());
        let bytes = minicbor::to_vec(&s).unwrap();
        assert!(bytes.windows(12).any(|w| w == b"admin_helper"));
        let back: ReadinessSnapshot = minicbor::decode(&bytes).unwrap();
        assert_eq!(back, s);
        assert_eq!(s.host_not_ready_cause(), None, "badge only");
        assert_eq!(row_title("admin_helper"), "Administrator helper registered");
        assert_eq!(row_title("panic_key"), "Panic key");

        let shared = SharedReadiness::new(ReadinessSnapshot::unknown());
        let reader = shared.clone();
        shared.set(s.clone());
        assert_eq!(reader.get(), s);
    }
}
