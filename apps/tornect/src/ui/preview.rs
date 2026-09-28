//! `tornect gui --preview`: every screen from synthetic state, with a moving
//! test card in the stream window, and nothing started (no Tor, no hosting, no
//! network). For looking at the window itself, headless under Xvfb included
//! (`docs/UI_PLAN.md` §10's harness in miniature; answers go nowhere).
//!
//! Nothing here reads this machine's state: the preview branches before the
//! window's set-up touches the Tornect home (review F-1), and every name, path
//! and ID it shows is made up, so that a picture of it shows nothing real.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tornect_capture::{TestCard, VideoSource as _};
use tornect_codec::DecodedFrame;
use tornect_core::address_book::Day;
use tornect_core::{DeviceId, TornectId};
use tornect_session::FrameSink as _;

use super::model::{
    Book, CaptureNote, ClientStage, Computer, Confirm, Device, Hosting, Model, Popup, PopupKind,
    Setup, Shared, Sharing, TorState, Viewing,
};
use super::stream::{FrameSlot, SlotSink};

/// What the setup card names: a stand-in, never a path of this machine.
const TOKEN_FILE: &str = "~/.local/share/tornect/portal-restore-token";

/// The preview's own ID: the onion address of an all-zero key, obviously
/// not a real computer's.
#[must_use]
pub fn synthetic_id() -> TornectId {
    TornectId::from_bytes([0; 32])
}

/// The preview's first model: `everything` puts one of everything on screen
/// at once; otherwise the window is at rest, for looking at a page. `empty`
/// shows an address book with nothing in it (a first run).
#[must_use]
pub fn model(everything: bool, empty: bool) -> Model {
    let today = Day::today();
    let mut m = Model {
        id: Some(synthetic_id().display_groups()),
        device_name: "Linux PC".to_owned(),
        book: if empty {
            Book {
                history: true,
                today: Some(today),
                ..Book::default()
            }
        } else {
            sample_book(today)
        },
        ..Model::default()
    };
    if everything {
        fill(&mut m);
    } else {
        rest(&mut m);
    }
    m
}

/// A made-up address book: invented names, and the IDs and host keys of
/// made-up keys.
fn sample_book(today: Day) -> Book {
    let id = |seed: u8| TornectId::from_bytes([seed; 32]);
    let fingerprint = |seed: u8| DeviceId::from_bytes([seed; 32]).fingerprint();
    let ago = |days: i64| Day::from_days(today.days() - days);
    let paired = |seed: u8, name: Option<&str>, label: &str, since: i64, last: i64| Computer {
        id: id(seed),
        name: name.map(str::to_owned),
        pinned: Some(label.to_owned()),
        declared: Some(label.to_owned()),
        fingerprint: Some(fingerprint(seed)),
        paired: Some(ago(since)),
        last_seen: Some(ago(last)),
        name_hidden: false,
    };
    Book {
        computers: vec![
            paired(0x31, Some("Office PC"), "Linux PC", 15, 0),
            paired(0x52, None, "Home server", 25, 3),
            paired(0x73, None, "Render box", 30, 14),
            Computer {
                id: id(0x94),
                name: Some("Studio laptop".to_owned()),
                pinned: None,
                declared: None,
                fingerprint: None,
                paired: None,
                last_seen: None,
                name_hidden: false,
            },
        ],
        recent: vec![
            (id(0x31), ago(0)),
            (id(0x52), ago(3)),
            (id(0x31), ago(5)),
            (id(0x73), ago(14)),
        ],
        devices: vec![
            Device {
                label: "Laptop".to_owned(),
                fingerprint: fingerprint(0xa5),
                paired: ago(4),
                last_seen: ago(1),
            },
            Device {
                label: "Tablet".to_owned(),
                fingerprint: fingerprint(0xb6),
                paired: ago(7),
                last_seen: ago(4),
            },
        ],
        history: true,
        today: Some(today),
        ..Book::default()
    }
}

/// Put one of everything on screen.
fn fill(m: &mut Model) {
    let now = Instant::now();
    m.tor = TorState::Ready {
        via: "obfs4 bridges",
    };
    m.hosting = Hosting::Published {
        reachable: true,
        state: "Running".to_owned(),
        problem: None,
    };
    m.setup = Some(Setup {
        token_file: PathBuf::from(TOKEN_FILE),
        granted: false,
        busy: false,
        note: None,
    });
    m.popups = vec![
        Popup {
            id: 1,
            kind: PopupKind::Pairing {
                name: "Laptop".to_owned(),
                fingerprint: "3f2a 91c0 77de 0b14".to_owned(),
                sas: "482 917".to_owned(),
                pinned: None,
            },
            deadline: now + Duration::from_secs(60),
        },
        Popup {
            id: 2,
            kind: PopupKind::Session {
                label: "Laptop".to_owned(),
                fingerprint: "3f2a 91c0 77de 0b14".to_owned(),
            },
            deadline: now + Duration::from_secs(60),
        },
    ];
    m.confirm = Some(Confirm {
        id: 3,
        host_name: "Office PC".to_owned(),
        sas: "305 116".to_owned(),
        host_waits_until: now + Duration::from_secs(50),
        deadline: now + Duration::from_secs(600),
    });
    m.sharing = vec![Sharing {
        session_id: "0123456789abcdef".to_owned(),
        label: "Laptop".to_owned(),
        control: true,
        unattended: false,
        since: now,
        capture: Some(CaptureNote {
            source: "wayland",
            width: 1920,
            height: 1080,
            input: true,
        }),
    }];
    m.client = ClientStage::Live(Viewing {
        host: "Office PC".to_owned(),
        control: true,
        since: now,
        pictures: 0,
        size: (0, 0),
    });
    m.note("preview: nothing here is real");
    // Nothing to shut down: closing the window quits at once.
    m.closed = true;
}

/// A window at rest, for looking at a page: Tor connected, this ID
/// reachable, the desktop's grant not given yet, a few things that happened;
/// no question open, no session, no stream window.
fn rest(m: &mut Model) {
    m.tor = TorState::Ready {
        via: "obfs4 bridges",
    };
    m.hosting = Hosting::Published {
        reachable: true,
        state: "Running".to_owned(),
        problem: None,
    };
    m.setup = Some(Setup {
        token_file: PathBuf::from(TOKEN_FILE),
        granted: false,
        busy: false,
        note: None,
    });
    m.note("preview: nothing here is real");
    m.note("Tor: connected via obfs4 bridges");
    m.note("this ID is published: paired devices can ask for a session");
    m.closed = true;
}

/// Feed the stream window a moving test card at 10 pictures a second, on a
/// thread of its own, for the life of the process.
pub fn card(slot: Arc<FrameSlot>, shared: Arc<Shared>) {
    let mut card = TestCard::new(1280, 720, 10);
    let mut sink = SlotSink::new(slot, shared);
    let mut seq = 0u32;
    loop {
        if let Ok(Some(frame)) = card.next_frame(Duration::from_millis(100)) {
            // BGRx to RGBA.
            let rgba = frame
                .bgrx
                .chunks_exact(4)
                .flat_map(|p| [p[2], p[1], p[0], 255])
                .collect();
            seq = seq.wrapping_add(1);
            sink.picture(
                seq,
                &DecodedFrame {
                    width: frame.width,
                    height: frame.height,
                    rgba,
                },
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use tornect_core::Paths;
    use tornect_session::Source;

    use super::super::{GuiOpts, Page, start};
    use super::*;

    fn opts(preview: bool, page: Option<Page>) -> GuiOpts {
        GuiOpts {
            source: Source::TestCard,
            host: true,
            bridges: None,
            preview,
            page,
            empty: false,
            theme: egui::Theme::Dark,
        }
    }

    /// Review F-1: the preview's set-up reads and writes nothing of this
    /// machine's. Under a fresh Tornect home it creates no file and no
    /// directory (no keystore, no identity, no configuration), and the ID it
    /// shows is the synthetic one; the window's own set-up, from the same
    /// home, creates the directories and the identities, so the check can
    /// fail.
    #[test]
    fn the_preview_touches_no_state_and_shows_a_made_up_id() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let paths = Paths::from_home(&home);
        let made_up = synthetic_id().display_groups();
        assert!(made_up.starts_with("aaaaaaaa aaaaaaaa"), "{made_up}");
        for page in [None, Some(Page::Home), Some(Page::AddressBook)] {
            let start = start(&paths, &opts(true, page)).unwrap();
            assert!(start.real.is_none(), "{page:?}: the preview starts nothing");
            assert_eq!(start.model.id.as_deref(), Some(made_up.as_str()));
            assert!(!home.exists(), "{page:?}: the preview created {home:?}");
            assert!(std::fs::read_dir(tmp.path()).unwrap().next().is_none());
        }
        let real = start(&paths, &opts(false, None)).unwrap();
        assert!(real.real.is_some());
        assert!(
            paths.keys_dir().is_dir(),
            "the window's set-up makes its home"
        );
        assert_ne!(real.model.id.as_deref(), Some(made_up.as_str()));
    }
}
