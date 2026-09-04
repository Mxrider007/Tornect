//! F3 (`docs/PLAN.md` §B.8.15, §B.8.5.3): the unattended store and limiter loaders
//! driven through the `Clock` trait with fuzzed wall / monotonic readings — the AEAD
//! file decoder on raw bytes, the load-time settlement / decay and the runtime decay
//! on arbitrary `FailState`s, and a whole `GrantStore` (host and offline loads) built
//! from a fuzz-generated store, then exercised by a fuzzed sequence of gate / charge /
//! settle / post-F2 / housekeeping calls interleaved with clock steps (forward, wall-only,
//! rollback). Nothing may panic; every persisted clock field stays monotone.
//!
//! ```text
//! TMPDIR=$PWD/target/tmp cargo +nightly fuzz run store -- -max_total_time=600
//! ```
//!
//! The first input byte selects the scenario; the rest is an `arbitrary::Unstructured`.
//! Scenario 3 writes a state directory under `std::env::temp_dir()` (one directory per
//! process, reused for every input; `TMPDIR` on the quota-limited dev VM).

#![no_main]

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use arbitrary::Unstructured;
use libfuzzer_sys::fuzz_target;
use tornect_core::id::DeviceId;
use tornect_core::keystore::{FileSecretStore, SecretStore};
use tornect_core::paths::Paths;
use tornect_core::session_log::{Actor, SessionLog, SessionMode, TransportKind};
use tornect_core::unattended::codec::{self, MASTER_KEY_ENTRY, MasterKey};
use tornect_core::unattended::grant::{
    AuthRecord, FailState, GrantState, LastUsed, Preset, SuspendReason, UnattendedGrant,
    UnattendedStore, Window,
};
use tornect_core::unattended::limiter::{
    AttemptLimiter, FailKind, HostTransport, Settle, decay_runtime,
};
use tornect_core::unattended::readiness::ReadinessSnapshot;
use tornect_core::unattended::schedule::FixedOffset;
use tornect_core::unattended::store::{
    GrantStore, LoadMode, RuntimeFail, StoreStatus, settle_and_decay_at_load,
};
use tornect_core::unattended::{Clock as _, FakeClock};
use zeroize::Zeroizing;

const K_MASTER: [u8; 32] = [0x5a; 32];

fn scratch() -> &'static Paths {
    static PATHS: OnceLock<Paths> = OnceLock::new();
    PATHS.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("tornect-fuzz-store-{}", std::process::id()));
        let paths = Paths::from_home(dir);
        paths.ensure().expect("scratch state dir");
        paths
    })
}

fn device(u: &mut Unstructured<'_>) -> arbitrary::Result<DeviceId> {
    // A small key space so ops hit existing grants often.
    let b = u.int_in_range(0u8..=3)?;
    Ok(DeviceId::from_bytes([b; 32]))
}

fn fail_state(u: &mut Unstructured<'_>) -> arbitrary::Result<FailState> {
    Ok(FailState {
        consecutive: u.arbitrary()?,
        since_unlock: u.arbitrary()?,
        pending: u.arbitrary()?,
        last_fail_at: u.arbitrary()?,
        lock_remaining_s: u.arbitrary()?,
        flushed_at: u.arbitrary()?,
        hard_locked: u.arbitrary()?,
        decay_anchor: u.arbitrary()?,
        lifetime_decay_anchor: u.arbitrary()?,
    })
}

fn wall(u: &mut Unstructured<'_>) -> arbitrary::Result<u64> {
    // Mostly plausible unix times, sometimes the whole range.
    Ok(if u.ratio(7u8, 8u8)? {
        u.int_in_range(0u64..=4_000_000_000)?
    } else {
        u.arbitrary()?
    })
}

fn grant(u: &mut Unstructured<'_>, now: u64) -> arbitrary::Result<UnattendedGrant> {
    let preset = match u.int_in_range(0u8..=2)? {
        0 => Preset::MyMachines,
        1 => Preset::HeadlessBox,
        _ => Preset::HelpingSomeone,
    };
    let auth = match u.int_in_range(0u8..=2)? {
        0 => AuthRecord::Opaque {
            record: Zeroizing::new(vec![0x11; usize::from(u.int_in_range(0u8..=200)?)]),
        },
        1 => AuthRecord::Spake2 {
            salt: u.arbitrary()?,
            wrapped_w: Zeroizing::new(vec![0x22; usize::from(u.int_in_range(0u8..=40)?)]),
        },
        _ => AuthRecord::Pruned,
    };
    let mut g = UnattendedGrant::from_preset(
        u.arbitrary()?,
        device(u)?,
        "fuzz",
        Actor::Ui,
        preset,
        1,
        auth,
        now,
    )
    .expect("a preset grant with a valid label");
    g.suite = u.int_in_range(0u8..=2)?;
    g.active_from = wall(u)?;
    g.expires_at = if u.arbitrary()? { Some(wall(u)?) } else { None };
    g.mode = if u.arbitrary()? {
        SessionMode::Control
    } else {
        SessionMode::ViewOnly
    };
    g.max_session_secs = if u.arbitrary()? {
        Some(u.arbitrary()?)
    } else {
        None
    };
    g.reconnect_cooldown_s = u.arbitrary()?;
    g.require_tor_only = u.arbitrary()?;
    g.hard_lock_after = u.int_in_range(0u32..=64)?;
    g.state = match u.int_in_range(0u8..=5)? {
        0 => GrantState::Active,
        1 => GrantState::Suspended {
            reason: SuspendReason::LocalBlock,
            since: wall(u)?,
        },
        2 => GrantState::Suspended {
            reason: SuspendReason::Admin,
            since: wall(u)?,
        },
        3 => GrantState::Suspended {
            reason: SuspendReason::Local { by: Actor::Cli },
            since: wall(u)?,
        },
        4 => GrantState::Disabled {
            since: wall(u)?,
            by: Actor::Import,
        },
        _ => GrantState::Active,
    };
    if u.arbitrary()? {
        let n = u.int_in_range(0usize..=3)?;
        let mut ws = Vec::with_capacity(n);
        for _ in 0..n {
            ws.push(Window {
                days: u.arbitrary()?,
                start_min: u.int_in_range(0u16..=1439)?,
                end_min: u.int_in_range(0u16..=1440)?,
                tz: "UTC".into(),
            });
        }
        g.schedule = Some(ws);
    }
    if u.arbitrary()? {
        g.last_used = Some(LastUsed {
            at: wall(u)?,
            transport: TransportKind::Direct,
            duration_secs: u.arbitrary()?,
        });
    }
    g.fail = fail_state(u)?;
    Ok(g)
}

fn store(u: &mut Unstructured<'_>, now: u64) -> arbitrary::Result<UnattendedStore> {
    let mut s = UnattendedStore::bootstrap(
        Zeroizing::new(vec![0x33; 128]),
        if u.arbitrary()? {
            Some(u.arbitrary()?)
        } else {
            None
        },
        now,
    );
    s.enabled = u.arbitrary()?;
    s.paused_until = if u.arbitrary()? { Some(wall(u)?) } else { None };
    s.stop_token = Some(u.arbitrary()?);
    s.last_seen_unix = wall(u)?;
    s.pending_anchor = u.int_in_range(0u64..=8)?;
    let n = u.int_in_range(0usize..=4)?;
    for _ in 0..n {
        let g = grant(u, now)?;
        if s.grant(&g.device).is_none() {
            s.grants.push(g);
        }
    }
    Ok(s)
}

/// Every persisted clock field of the loaded store is ≥ what was on disk (§B.8.5.3).
fn assert_monotone(before: &UnattendedStore, after: &UnattendedStore) {
    assert!(
        after.last_seen_unix >= before.last_seen_unix,
        "last_seen decreased"
    );
    for b in &before.grants {
        if let Some(a) = after.grant(&b.device) {
            assert!(
                a.fail.decay_anchor >= b.fail.decay_anchor,
                "decay_anchor decreased"
            );
            assert!(
                a.fail.lifetime_decay_anchor >= b.fail.lifetime_decay_anchor,
                "lifetime anchor decreased"
            );
            assert!(
                a.fail.flushed_at >= b.fail.flushed_at,
                "flushed_at decreased"
            );
            assert!(
                b.fail.hard_locked <= a.fail.hard_locked
                    || !b.fail.hard_locked
                    || a.fail.since_unlock == 0 && a.fail.consecutive == 0,
                "hard lock cleared by something other than an unlock"
            );
        }
    }
}

fn scenario_loader(u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
    let paths = scratch();
    let now = wall(u)?;
    let mono = Duration::from_secs(u.arbitrary()?);
    let generation: u64 = u.int_in_range(0u64..=8)?;
    let anchor: u64 = u.int_in_range(0u64..=8)?;
    let offline = u.arbitrary()?;
    let machine_id: Option<Vec<u8>> = if u.arbitrary()? {
        Some(b"fuzz-machine".to_vec())
    } else {
        None
    };
    let original = store(u, now)?;

    // Prepare the state dir: sealed file + keystore entry with the fuzzed anchor.
    let secrets = Arc::new(FileSecretStore::open(paths.keys_dir()).expect("keystore"));
    let master = MasterKey::from_parts(K_MASTER, anchor);
    secrets
        .put(MASTER_KEY_ENTRY, &master.to_entry())
        .expect("put master key");
    let sealed = codec::seal(&master.k_unatt(), generation, &original).expect("seal");
    std::fs::write(paths.unattended_store(), &sealed).expect("write store");
    let _ = std::fs::remove_file(paths.sessions_log());

    let clock = Arc::new(FakeClock::new(now, mono));
    let log = SessionLog::new(paths.sessions_log());
    let mode = if offline {
        LoadMode::Offline
    } else {
        LoadMode::Host
    };
    let gs =
        GrantStore::open_with_mode(paths, secrets.clone(), clock.clone(), log, machine_id, mode)
            .expect("open never fails on a prepared dir");
    match gs.status() {
        StoreStatus::Loaded => {}
        StoreStatus::FailedClosed(_) => {
            // The anchor rule or the pending-anchor bump refused the file: fine, done.
            let lim = AttemptLimiter::new(gs.clone());
            let _ = lim.gate(&DeviceId::from_bytes([0; 32]), 1, &[1]);
            let _ = lim.charge(&DeviceId::from_bytes([0; 32]));
            return Ok(());
        }
        StoreStatus::AttendedOnly => panic!("a store file with a key can never be attended-only"),
    }
    let loaded = gs.read(|s| s.clone()).expect("loaded");
    assert_monotone(&original, &loaded);
    if offline {
        for g in &original.grants {
            let l = gs.grant(&g.device).expect("same grants");
            assert_eq!(l.fail, g.fail, "offline load leaves FailState untouched");
        }
    } else {
        for g in &loaded.grants {
            assert!(!g.fail.pending, "pending settled at load");
        }
    }

    // A fuzzed sequence of limiter / clock operations.
    let lim = AttemptLimiter::new(gs.clone());
    let tz = FixedOffset::utc();
    let ops = u.int_in_range(0usize..=16)?;
    let mut prev_last_seen = gs.last_seen().unwrap_or(0);
    for _ in 0..ops {
        let d = device(u)?;
        match u.int_in_range(0u8..=9)? {
            0 => clock.advance(Duration::from_secs(u.int_in_range(0u64..=3 * 86_400)?)),
            1 => clock.advance_wall(u.int_in_range(0u64..=3 * 86_400)?),
            2 => clock.advance_mono(Duration::from_secs(u.int_in_range(0u64..=3600)?)),
            3 => clock.set_wall(clock.wall().saturating_sub(u.int_in_range(0u64..=86_400)?)),
            4 => {
                let _ = lim.gate(&d, u.int_in_range(0u8..=2)?, &[1]);
            }
            5 => {
                let _ = lim.charge(&d);
            }
            6 => {
                let outcome = if u.arbitrary()? {
                    Settle::Ok
                } else {
                    Settle::Fail(FailKind::BadKe3)
                };
                let _ = lim.settle(&d, outcome);
            }
            7 => {
                let host = HostTransport {
                    paranoid: u.arbitrary()?,
                    lan_only: u.arbitrary()?,
                };
                let _ = lim.post_f2(&d, &tz, host);
            }
            8 => {
                let _ = gs.housekeeping();
            }
            _ => {
                let rep = gs.status_report(ReadinessSnapshot::unknown());
                assert!(rep.grants.len() <= 4);
                let _ = gs.lock_remaining_s(&d);
            }
        }
        // last_seen never decreases in memory whatever the clock did
        let ls = gs.last_seen().unwrap_or(0);
        assert!(ls >= prev_last_seen, "last_seen went backwards");
        prev_last_seen = ls;
        if let Some(after) = gs.read(|s| s.clone()) {
            assert_monotone(&loaded, &after);
        }
    }
    let _ = gs.verify_log();
    drop((lim, gs));
    // The file left behind must load again (host mode) or fail closed — never panic.
    let clock2 = Arc::new(FakeClock::new(
        wall(u)?,
        Duration::from_secs(u.arbitrary()?),
    ));
    let again = GrantStore::open_with_machine_id(
        paths,
        secrets,
        clock2,
        SessionLog::new(paths.sessions_log()),
        None,
    )
    .expect("reopen");
    let _ = again.status();
    let _ = again.status_report(ReadinessSnapshot::unknown());
    Ok(())
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let mut u = Unstructured::new(rest);
    match mode % 4 {
        0 => {
            // The AEAD file decoder on raw bytes, under the fixed key and a random one.
            let _ = codec::parse_header(rest);
            let _ = codec::open(&codec::derive_k_unatt(&K_MASTER), rest);
            let _ = codec::open(&[0; 32], rest);
            let _ = MasterKey::parse(rest);
            let _ = minicbor::decode::<UnattendedStore>(rest);
            let _ = minicbor::decode::<UnattendedGrant>(rest);
            let _ = minicbor::decode::<FailState>(rest);
        }
        1 => {
            // Load-time settlement / decay on any FailState with any readings.
            let Ok(mut f) = fail_state(&mut u) else {
                return;
            };
            let before = f;
            let now = wall(&mut u).unwrap_or(0);
            let mono = Duration::new(
                u.arbitrary().unwrap_or(0),
                u.int_in_range(0u32..=999_999_999).unwrap_or(0),
            );
            let rollback = u.arbitrary().unwrap_or(false);
            let (rt, settled) = settle_and_decay_at_load(&mut f, now, mono, rollback);
            assert_eq!(settled, before.pending);
            assert!(!f.pending);
            assert!(f.decay_anchor >= before.decay_anchor);
            assert!(f.lifetime_decay_anchor >= before.lifetime_decay_anchor);
            assert!(f.consecutive <= before.consecutive);
            assert!(f.since_unlock >= before.since_unlock.saturating_sub(1));
            assert_eq!(f.hard_locked, before.hard_locked);
            assert_eq!(rt.locked_until.is_some(), f.lock_remaining_s > 0);
            if rollback {
                assert_eq!(f.consecutive, before.consecutive);
                assert_eq!(f.lock_remaining_s, before.lock_remaining_s);
            }
        }
        2 => {
            // Runtime decay on the monotonic twins with any credit / twin / reading.
            let Ok(mut f) = fail_state(&mut u) else {
                return;
            };
            let mut rt = RuntimeFail {
                decay_twin: Duration::from_secs(u.arbitrary().unwrap_or(0)),
                decay_credit: u.arbitrary().unwrap_or(0),
                lifetime_twin: Duration::from_secs(u.arbitrary().unwrap_or(0)),
                lifetime_credit: u.arbitrary().unwrap_or(0),
                ..RuntimeFail::default()
            };
            let before = f;
            let steps = u.int_in_range(1usize..=8).unwrap_or(1);
            let mut mono = Duration::from_secs(u.arbitrary().unwrap_or(0));
            for _ in 0..steps {
                decay_runtime(&mut f, &mut rt, mono);
                assert!(f.decay_anchor >= before.decay_anchor);
                assert!(f.lifetime_decay_anchor >= before.lifetime_decay_anchor);
                assert!(f.consecutive <= before.consecutive);
                assert!(f.since_unlock <= before.since_unlock);
                assert_eq!(f.hard_locked, before.hard_locked);
                mono = mono
                    .checked_add(Duration::from_secs(
                        u.int_in_range(0u64..=10 * 86_400).unwrap_or(0),
                    ))
                    .unwrap_or(Duration::MAX);
            }
        }
        _ => {
            let _ = scenario_loader(&mut u);
        }
    }
});
