//! `tornect gui --preview`: every screen from synthetic state, with a moving
//! test card in the stream window, and nothing started (no Tor, no hosting, no
//! network). For looking at the window itself, headless under Xvfb included
//! (`docs/UI_PLAN.md` §10's harness in miniature; answers go nowhere).

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tornect_capture::{TestCard, VideoSource as _};
use tornect_codec::DecodedFrame;
use tornect_session::FrameSink as _;

use super::model::{
    CaptureNote, ClientStage, Confirm, Hosting, Popup, PopupKind, Setup, Shared, Sharing, TorState,
    Viewing,
};
use super::stream::{FrameSlot, SlotSink};

/// Put one of everything on screen.
pub fn fill(shared: &Shared, token_file: &Path) {
    let now = Instant::now();
    shared.update(|m| {
        m.tor = TorState::Ready {
            via: "obfs4 bridges",
        };
        m.hosting = Hosting::Published {
            reachable: true,
            state: "Running".to_owned(),
            problem: None,
        };
        m.setup = Some(Setup {
            token_file: token_file.to_owned(),
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
            deadline: now + Duration::from_secs(50),
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
    });
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
