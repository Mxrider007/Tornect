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
use tornect_codec::{DecodeTiming, DecodedFrame};
use tornect_core::TornectId;
use tornect_core::address_book::Day;
use tornect_core::config::QualityPreset;
use tornect_core::levels::{Availability, WindowsFacts};
use tornect_core::words::{Identicon, Words};
use tornect_proto::{HostStats, MonitorEntry, QualityInfo};
use tornect_session::FrameSink as _;

use super::model::{
    Book, CaptureNote, ClientStage, Computer, Confirm, Device, Dial, Failure, Hosting, Model,
    MyWords, Popup, PopupKind, Recognition, ScreensView, Settings, Setup, Shared, Sharing,
    SheetLevels, StreamInfo, TorState, UaRecord, Viewing,
};
use super::pages::viewer::ViewerState;
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
        settings: Settings {
            device_name: "Linux PC".to_owned(),
            ..Settings::default()
        },
        book: if empty {
            Book {
                history: true,
                today: Some(today),
                ..Book::default()
            }
        } else {
            sample_book(today)
        },
        mine: Some(MyWords {
            device: words("orient walk nice rally"),
            address: words("treat fame transfer pride"),
        }),
        ..Model::default()
    };
    if everything {
        fill(&mut m);
    } else {
        rest(&mut m);
    }
    m
}

/// Invented device words (four words of the list; no key behind them).
fn words(text: &str) -> Words {
    Words::from_cached(text).unwrap_or_else(|| unreachable!("four words of the list"))
}

/// Which host sheet `--preview --sheet` puts on screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sheet {
    /// A new device asks to pair: its words, not yet trusted.
    New,
    /// A paired device asks to pair again: its saved name and identicon.
    Pinned,
    /// A new device that looks like a saved one: the alarm, the typed code.
    Alarm,
    /// A paired device asks for a session.
    Session,
    /// The session sheet with this computer's levels: Linux's three answers
    /// and its sentence (§B.2.1).
    SessionLinux,
    /// The session sheet of a Windows host where every program runs as
    /// administrator (UAC off): View only and "Allow as administrator".
    SessionAdmin,
    /// That sheet after "Allow as administrator": its Tornect confirmation.
    AdminConfirm,
    /// The session sheet of an invented installed Windows host, UAC on, as
    /// this build offers it (no administrator helper yet).
    SessionWindows,
    /// That row with the administrator helper (M-FEAT-3): the four answers,
    /// "Allow as administrator…" asking Windows.
    SessionFour,
    /// The four-answer sheet after its Windows prompt failed.
    AdminNotGiven,
    /// The session sheet of an invented administrator account that
    /// elevates without prompting.
    SessionNoPrompt,
    /// That row with the administrator helper (M-FEAT-3; the operator's
    /// ruling of 2026-09-29): View only and "Allow as administrator", for a
    /// device paired moments before (the scam line).
    NoPromptHelper,
    /// That sheet's Tornect confirmation.
    NoPromptConfirm,
    /// A pairing and a session question open at once.
    TwoOpen,
    /// The connect stepper, reaching the computer.
    StageReaching,
    /// The connect stepper, pairing (with the code question open).
    StagePairing,
    /// The connect stepper, waiting for approval.
    StageAsking,
    /// The connect stepper, connected at the administrator level.
    StageLive,
    /// The connect stepper after the computer could not be reached.
    StageUnreachable,
    /// The connect stepper after the person there said no.
    StageDenied,
    /// The connect stepper after the codes differed.
    StageCodesDiffer,
    /// A saved computer where connecting without asking worked: Connect
    /// comes first on its card (§B.8.10).
    UaCard,
    /// The password prompt of an unattended connect, Remember offered.
    UaPrompt,
    /// The connect stepper after an unattended connect was refused.
    UaRefused,
    /// The connect stepper with an unattended session live: the badge.
    UaLive,
    /// History off: Home's first-run line, and the address book's Recent
    /// tab (F4-M1).
    HistoryOff,
    /// Forget's confirmation, open on the made-up book's first computer.
    ForgetAsk,
    /// The Unlock confirmation with the typed device's words (F4-4).
    UaUnlock,
    /// The connect field filled from a `tornect:` link (design `invite`
    /// §2.2): its note, and Connect waiting a second after it is seen.
    LinkFilled,
    /// The stream window's Quality menu with a pick on its way: "Changing…"
    /// under it for its first 10 s (the quality design §3.2).
    ViewerQuality,
    /// The stream window's details with the Quality and Timing rows (the
    /// quality design §3.3).
    ViewerDetails,
    /// The stream window's Screens menu: two screens, the main one shown,
    /// and "All screens" (the monitors design §2).
    ViewerScreens,
}

impl Sheet {
    /// What the stream window opens with for this sheet, if it is one of
    /// the stream window's.
    #[must_use]
    pub fn stream(self) -> Option<StreamSheet> {
        match self {
            Self::ViewerQuality => Some(StreamSheet::QualityMenu),
            Self::ViewerDetails => Some(StreamSheet::Details),
            Self::ViewerScreens => Some(StreamSheet::ScreensMenu),
            _ => None,
        }
    }
}

/// What the preview's stream window opens with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamSheet {
    /// The Quality menu, a pick of Balanced on its way.
    QualityMenu,
    /// The details.
    Details,
    /// The Screens menu.
    ScreensMenu,
}

/// Open the preview's stream window `viewer` as `sheet` shows it, the
/// toolbar pinned so that it stays.
pub fn open_stream(sheet: StreamSheet, viewer: &mut ViewerState, now: Instant) {
    viewer.pinned = true;
    match sheet {
        StreamSheet::QualityMenu => {
            viewer.pick_quality(
                QualityPreset::Balanced,
                Some(QualityPreset::BestPerformance),
                now,
            );
            viewer.quality_menu = true;
        }
        StreamSheet::Details => viewer.details = true,
        StreamSheet::ScreensMenu => viewer.screens_menu = true,
    }
}

/// What the preview's host says it applies: Best performance, whose cap
/// is the test card's 1280 × 720.
fn sample_quality() -> QualityInfo {
    QualityInfo {
        preset: tornect_session::quality::code(QualityPreset::BestPerformance),
        max_fps: 20,
        kbps: 1000,
        max_long: 1280,
        max_short: 720,
    }
}

/// The preview's host means: invented numbers, a 2560 × 1440 desktop.
fn sample_host() -> HostStats {
    HostStats {
        source_width: 2560,
        source_height: 1440,
        frames: 10,
        window_ms: 1000,
        grab_us: 4000,
        age_us: 6200,
        scale_us: 2100,
        convert_us: 1500,
        encode_us: 9800,
        send_us: 120_000,
        ack_us: 1_100_000,
    }
}

/// The preview's stream as the host would describe it, with this
/// computer's invented means.
fn sample_stream() -> StreamInfo {
    let mut stream = StreamInfo {
        applied: Some(sample_quality()),
        announced: (1280, 720),
        host: Some(sample_host()),
        ..StreamInfo::default()
    };
    stream.decode_ms.add(3.1);
    stream.convert_ms.add(1.2);
    stream
}

/// A live session viewed at the control level, of the made-up "Office
/// PC", for the stream window's sheets.
fn viewed(now: Instant) -> Viewing {
    Viewing {
        host: "Office PC".to_owned(),
        control: true,
        administrator: false,
        unattended: false,
        since: now,
        pictures: 0,
        size: (0, 0),
        stream: sample_stream(),
        services: None,
        screens: Some(sample_screens()),
    }
}

/// The preview's host screens: two, side by side, the main one shown, and
/// "All screens" offered. Invented, as the rest.
fn sample_screens() -> ScreensView {
    ScreensView {
        monitors: vec![
            MonitorEntry::saturating(true, 0, 0, 2560, 1440),
            MonitorEntry::saturating(false, 2560, 0, 1920, 1080),
        ],
        all: true,
        shown: 1,
        ..ScreensView::default()
    }
}

/// Put one host sheet of `sheet`'s kind on screen, with invented words.
pub fn sheet(m: &mut Model, sheet: Sheet) {
    let deadline = Instant::now() + Duration::from_secs(60);
    if stage(m, sheet) || unattended(m, sheet) || book(m, sheet) {
        return;
    }
    if sheet.stream().is_some() {
        m.client = ClientStage::Live(viewed(Instant::now()));
        return;
    }
    let (kind, seen) = match sheet {
        Sheet::New | Sheet::Alarm => (
            PopupKind::Pairing {
                name: if sheet == Sheet::Alarm {
                    "Office PC".to_owned()
                } else {
                    "Laptop".to_owned()
                },
                fingerprint: String::new(),
                sas: "482 917".to_owned(),
                pinned: None,
            },
            Recognition {
                words: words("absurd citizen dinner harvest"),
                identicon: None,
                looks_like: (sheet == Sheet::Alarm).then(|| "Office PC".to_owned()),
                unchecked: false,
            },
        ),
        Sheet::Pinned => (
            PopupKind::Pairing {
                name: "Laptop".to_owned(),
                fingerprint: String::new(),
                sas: "482 917".to_owned(),
                pinned: Some("Laptop".to_owned()),
            },
            Recognition {
                words: words("orbit crisp lamp arctic"),
                identicon: Some(Identicon::from_seed([0x5a, 0x3c, 0x02])),
                looks_like: None,
                unchecked: false,
            },
        ),
        _ => (
            PopupKind::Session {
                label: "Laptop".to_owned(),
                fingerprint: String::new(),
            },
            Recognition {
                words: words("orbit crisp lamp arctic"),
                identicon: Some(Identicon::from_seed([0x5a, 0x3c, 0x02])),
                looks_like: None,
                unchecked: false,
            },
        ),
    };
    m.popups = vec![Popup {
        id: 7,
        kind,
        deadline,
    }];
    m.recognition.insert(7, seen);
    // Invented rows of the §B.2.1 table: nothing of this machine is read.
    let always_admin = || {
        Availability::of(Some(&WindowsFacts {
            installed: true,
            administrator: true,
            enable_lua: Some(0),
            ..WindowsFacts::default()
        }))
    };
    match sheet {
        Sheet::SessionLinux => {
            m.levels.insert(7, SheetLevels::of(&Availability::LINUX));
        }
        Sheet::SessionAdmin => {
            m.levels.insert(7, SheetLevels::of(&always_admin()));
        }
        Sheet::AdminConfirm => {
            m.levels.insert(7, SheetLevels::of(&always_admin()));
            m.admin_confirm.insert(7);
        }
        Sheet::SessionWindows | Sheet::SessionFour | Sheet::AdminNotGiven => {
            let installed = Availability::of(Some(&WindowsFacts {
                installed: true,
                administrator: true,
                ..WindowsFacts::default()
            }));
            let mut levels = SheetLevels::of(&installed);
            if sheet != Sheet::SessionWindows {
                // What the row offers once the helper exists (M-FEAT-3).
                levels.answers = installed.answers;
                levels.sentence = installed.sentence;
            }
            m.levels.insert(7, levels);
            if sheet == Sheet::AdminNotGiven {
                m.admin_not_given.insert(7);
            }
        }
        Sheet::SessionNoPrompt => {
            let no_prompt = Availability::of(Some(&WindowsFacts {
                installed: true,
                administrator: true,
                consent_prompt_behavior_admin: Some(0),
                ..WindowsFacts::default()
            }));
            m.levels.insert(7, SheetLevels::of(&no_prompt));
        }
        Sheet::NoPromptHelper | Sheet::NoPromptConfirm => {
            let no_prompt = Availability::of(Some(&WindowsFacts {
                installed: true,
                administrator: true,
                consent_prompt_behavior_admin: Some(0),
                ..WindowsFacts::default()
            }));
            // What the row offers once the helper is on.
            let mut levels = SheetLevels::of(&no_prompt);
            levels.answers = no_prompt.answers;
            levels.sentence = no_prompt.sentence;
            m.levels.insert(7, levels);
            m.paired_recently.insert(7);
            if sheet == Sheet::NoPromptConfirm {
                m.admin_confirm.insert(7);
            }
        }
        Sheet::TwoOpen => {
            m.levels.insert(7, SheetLevels::of(&Availability::LINUX));
            m.popups.insert(
                0,
                Popup {
                    id: 6,
                    kind: PopupKind::Pairing {
                        name: "Tablet".to_owned(),
                        fingerprint: String::new(),
                        sas: "482 917".to_owned(),
                        pinned: None,
                    },
                    deadline,
                },
            );
            m.recognition.insert(
                6,
                Recognition {
                    words: words("kid print proud pilot"),
                    identicon: None,
                    looks_like: None,
                    unchecked: false,
                },
            );
        }
        _ => {}
    }
}

/// The unattended client's screens for `--sheet ua-…` (§B.8.10), on the
/// made-up book's first computer; `false` for any other sheet.
fn unattended(m: &mut Model, sheet: Sheet) -> bool {
    use tornect_core::unattended::credentials::RememberOffer;
    use tornect_signal::messages::{SessionReject, reject};
    let now = Instant::now();
    let Some(first) = m.book.computers.first_mut() else {
        return false;
    };
    let (id, host) = (first.id, first.title());
    match sheet {
        Sheet::UaCard => {
            first.unattended = UaRecord {
                worked_before: true,
                remembered: true,
                control: true,
            };
        }
        Sheet::UaPrompt => {
            first.unattended.worked_before = true;
            m.prompt = Some(super::model::Prompt {
                id,
                host,
                keychain: Some("the kernel keyring of your user account"),
                kept: Some(tornect_core::unattended::credentials::KEYUTILS_KEPT),
                remember: (RememberOffer::Offered, RememberOffer::NotForAdministrator),
                remembered: false,
                vanished: false,
                stale: false,
                may_admin: false,
                retry_at: None,
                admin: None,
                target: None,
            });
        }
        Sheet::UaUnlock => {
            first.unattended = UaRecord {
                worked_before: true,
                remembered: false,
                control: true,
            };
            m.unlock_words = Some((
                *unlock_device().public_key_bytes(),
                words("economy bench equip pencil"),
            ));
        }
        Sheet::UaRefused | Sheet::UaLive => {
            first.unattended.worked_before = true;
            m.dial = Dial {
                id: Some(id),
                since: Some(now - Duration::from_secs(34)),
                paired_now: false,
                failed: (sheet == Sheet::UaRefused).then_some((Failure::NotLetIn, 2)),
                unattended: true,
                went_live: sheet == Sheet::UaLive,
            };
            m.client = if sheet == Sheet::UaRefused {
                ClientStage::Ended(crate::ua_client::reject_text(
                    &SessionReject {
                        reason: reject::HARD_LOCKED,
                        cause: None,
                        retry_after_s: None,
                        next_open_in_s: None,
                        detail: None,
                    },
                    &host,
                ))
            } else {
                m.ua_live = Some(super::model::UaLive {
                    withheld: false,
                    fail_summary: Some("3 failed attempts since your last login".to_owned()),
                });
                ClientStage::Live(Viewing {
                    host,
                    control: true,
                    administrator: false,
                    unattended: true,
                    since: now,
                    pictures: 1,
                    size: (1920, 1080),
                    stream: StreamInfo::default(),
                    services: None,
                    screens: None,
                })
            };
        }
        _ => return false,
    }
    true
}

/// The address book's states for `--sheet history-off` and `forget-ask`
/// (and `link-filled`, whose fill is the window's own);
/// `false` for any other sheet.
fn book(m: &mut Model, sheet: Sheet) -> bool {
    match sheet {
        Sheet::HistoryOff => {
            m.history_notice = true;
            m.book.history = false;
            m.book.recent.clear();
        }
        Sheet::ForgetAsk | Sheet::LinkFilled => {}
        _ => return false,
    }
    true
}

/// The other device an Unlock names in the preview: a made-up key.
fn unlock_device() -> tornect_core::DeviceId {
    tornect_core::DeviceIdentity::from_seed(&[0x5a; 32]).id()
}

/// The ID `--sheet link-filled` fills in: a made-up key's, whose seed is
/// no machine's.
fn link_id() -> TornectId {
    tornect_core::HostIdentity::from_seed(&[0x4c; 32]).id()
}

/// What `--sheet` opens in the window itself (a tab, a confirmation, a
/// link's fill), on the made-up book's first computer `first`.
pub fn form(form: &mut super::view::Form, sheet: Sheet, first: Option<TornectId>) {
    if sheet == Sheet::LinkFilled {
        form.link_arrived(
            tornect_core::unattended::ipc::ShownLink::Fill(link_id()),
            Some(synthetic_id()),
        );
        return;
    }
    let Some(first) = first else {
        return;
    };
    match sheet {
        Sheet::HistoryOff => form.book.tab = super::pages::Tab::Recent,
        Sheet::ForgetAsk => form.book.forgetting = Some(first),
        Sheet::UaUnlock => {
            let device = unlock_device();
            form.ua.unlocking = Some((first, device.to_string()));
            form.ua.words_asked = Some(*device.public_key_bytes());
        }
        _ => {}
    }
}

/// A taller main window for a sheet whose card sits low on its page (Forget's
/// confirmation: the line under its answers).
#[must_use]
pub fn height(sheet: Sheet) -> Option<f64> {
    matches!(sheet, Sheet::UaUnlock | Sheet::ForgetAsk).then_some(1150.0)
}

/// The connect stepper's stages for `--sheet stage-…`, with an invented
/// ID; `false` for a host sheet.
fn stage(m: &mut Model, sheet: Sheet) -> bool {
    let now = Instant::now();
    let id = TornectId::from_bytes([0x42; 32]);
    let failed = match sheet {
        Sheet::StageUnreachable => Some((Failure::Unreachable, 1)),
        Sheet::StageDenied => Some((Failure::Denied, 3)),
        Sheet::StageCodesDiffer => Some((Failure::CodesDiffer, 2)),
        _ => None,
    };
    m.client = match sheet {
        Sheet::StageReaching => ClientStage::Reaching {
            id: id.display_groups(),
        },
        Sheet::StagePairing => {
            m.confirm = Some(Confirm {
                id: 3,
                host_name: "Office PC".to_owned(),
                sas: "305 116".to_owned(),
                host_waits_until: now + Duration::from_secs(50),
                deadline: now + Duration::from_secs(600),
            });
            ClientStage::Pairing {
                sas: "305 116".to_owned(),
            }
        }
        Sheet::StageAsking => ClientStage::Asking,
        Sheet::StageLive => ClientStage::Live(Viewing {
            host: "Office PC".to_owned(),
            control: true,
            administrator: true,
            unattended: false,
            since: now,
            pictures: 1,
            size: (1920, 1080),
            stream: StreamInfo::default(),
            services: None,
            screens: None,
        }),
        Sheet::StageUnreachable => ClientStage::Ended(
            "The host is offline or has not finished publishing its Tornect ID.".to_owned(),
        ),
        Sheet::StageDenied => ClientStage::Ended("The host's user refused the session.".to_owned()),
        Sheet::StageCodesDiffer => {
            ClientStage::Ended("Not paired: you answered that the codes differ.".to_owned())
        }
        _ => return false,
    };
    m.dial = Dial {
        id: Some(id),
        since: Some(now - Duration::from_secs(21)),
        paired_now: sheet != Sheet::StageAsking,
        failed,
        unattended: false,
        went_live: sheet == Sheet::StageLive,
    };
    true
}

/// A made-up address book: invented names, and the IDs and host keys of
/// made-up keys, with invented words.
fn sample_book(today: Day) -> Book {
    let id = |seed: u8| TornectId::from_bytes([seed; 32]);
    let ago = |days: i64| Day::from_days(today.days() - days);
    let paired =
        |seed: u8, name: Option<&str>, label: &str, since: i64, last: i64, said: &str| Computer {
            id: id(seed),
            name: name.map(str::to_owned),
            pinned: Some(label.to_owned()),
            declared: Some(label.to_owned()),
            words: Some(words(said)),
            identicon: Some(Identicon::from_seed([seed, seed.rotate_left(3), seed])),
            paired: Some(ago(since)),
            last_seen: Some(ago(last)),
            name_hidden: false,
            unattended: UaRecord::default(),
        };
    Book {
        computers: vec![
            paired(
                0x31,
                Some("Office PC"),
                "Linux PC",
                15,
                0,
                "arctic crisp lamp orbit",
            ),
            paired(0x52, None, "Home server", 25, 3, "cream always equal idea"),
            paired(
                0x73,
                None,
                "Render box",
                30,
                14,
                "magic arrive umbrella annual",
            ),
            Computer {
                id: id(0x94),
                name: Some("Studio laptop".to_owned()),
                pinned: None,
                declared: None,
                words: Some(words("economy bench equip pencil")),
                identicon: None,
                paired: None,
                last_seen: None,
                name_hidden: false,
                unattended: UaRecord::default(),
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
                id: tornect_core::DeviceId::from_bytes([0x5a; 32]),
                label: "Laptop".to_owned(),
                words: Some(words("orbit crisp lamp arctic")),
                identicon: Some(Identicon::from_seed([0x5a, 0x3c, 0x02])),
                paired: ago(4),
                last_seen: ago(1),
            },
            Device {
                id: tornect_core::DeviceId::from_bytes([0xb6; 32]),
                label: "Tablet".to_owned(),
                words: Some(words("kid print proud pilot")),
                identicon: Some(Identicon::from_seed([0xb6, 0x21, 0x05])),
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
                fingerprint: String::new(),
                sas: "482 917".to_owned(),
                pinned: None,
            },
            deadline: now + Duration::from_secs(60),
        },
        Popup {
            id: 2,
            kind: PopupKind::Session {
                label: "Laptop".to_owned(),
                fingerprint: String::new(),
            },
            deadline: now + Duration::from_secs(60),
        },
    ];
    m.recognition.insert(
        1,
        Recognition {
            words: words("absurd citizen dinner harvest"),
            identicon: None,
            looks_like: None,
            unchecked: false,
        },
    );
    m.recognition.insert(
        2,
        Recognition {
            words: words("orbit crisp lamp arctic"),
            identicon: Some(Identicon::from_seed([0x5a, 0x3c, 0x02])),
            looks_like: None,
            unchecked: false,
        },
    );
    m.confirm = Some(Confirm {
        id: 3,
        host_name: "Office PC".to_owned(),
        sas: "305 116".to_owned(),
        host_waits_until: now + Duration::from_secs(50),
        deadline: now + Duration::from_secs(600),
    });
    // The shared session runs at the administrator level the host signed:
    // the banner and the indicator say so.
    m.admin_sessions.insert("0123456789abcdef".to_owned());
    m.sharing = vec![Sharing {
        session_id: "0123456789abcdef".to_owned(),
        label: "Laptop".to_owned(),
        control: true,
        unattended: false,
        since: now,
        services: None,
        capture: Some(CaptureNote {
            source: "wayland",
            width: 1920,
            height: 1080,
            input: true,
            shown: None,
            all: false,
            screens: 0,
        }),
    }];
    m.client = ClientStage::Live(viewed(now));
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
/// thread of its own, for the life of the process, with what a host would
/// say of it (invented numbers).
pub fn card(slot: Arc<FrameSlot>, shared: Arc<Shared>) {
    let mut card = TestCard::new(1280, 720, 10);
    let mut sink = SlotSink::new(slot, shared);
    sink.quality(1280, 720, &sample_quality());
    sink.host_stats(&sample_host());
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
                    timing: DecodeTiming {
                        decode: Duration::from_micros(3100),
                        convert: Duration::from_micros(1200),
                    },
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
            sheet: None,
            theme: egui::Theme::Dark,
            link: None,
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

    /// `--sheet link-filled` fills the connect field from a made-up link
    /// as a real link does (its note, Home), with or without a made-up
    /// book, and adds no question or stage to the model.
    #[test]
    fn the_link_sheet_fills_the_field_as_a_link_does() {
        let first = model(false, false).book.computers.first().map(|c| c.id);
        for first in [first, None] {
            let mut filled = super::super::view::Form::default();
            form(&mut filled, Sheet::LinkFilled, first);
            assert_eq!(filled.connect_to, link_id().display_groups());
            assert_eq!(
                filled.link_notes().collect::<Vec<_>>(),
                vec![super::super::view::LinkNote::Filled(link_id())]
            );
        }
        let mut book = model(false, false);
        let before = format!("{book:?}");
        sheet(&mut book, Sheet::LinkFilled);
        assert_eq!(format!("{book:?}"), before, "no question, no stage");
    }

    /// `--sheet viewer-quality` and `--sheet viewer-details` (the quality
    /// design §3.2, §3.3): a live session with what a host would say of it,
    /// and the stream window opens pinned, with its Quality menu and a pick
    /// of Balanced on its way ("Changing…" under it, the applied Best
    /// performance checked), or with its details and their Quality and
    /// Timing rows. `--sheet viewer-screens` (the monitors design §2): its
    /// Screens menu, two screens and all of them, the main one shown. No
    /// other sheet opens the stream window so.
    #[test]
    fn the_stream_sheets_show_the_quality_menu_and_the_timing_rows() {
        use super::super::pages::viewer::testing::Window;
        let ms = Duration::from_millis;
        let menu: &[&str] = &[
            "Best quality",
            "Balanced",
            "Best performance",
            "Changing…",
            "Tor relay · Best performance · 0 fps · 1280×720",
        ];
        let details: &[&str] = &[
            "Best performance · up to 20 fps · 1.0 Mbit/s",
            "Scaled down from 2560×1440",
            "Remote computer: capture 4.0 ms · scale 2.1 ms · convert 1.5 ms · encode 9.8 ms · \
             send 120 ms",
            "Round trip: 1.1 s",
        ];
        let screens: &[&str] = &[
            "Screen 1",
            "Screen 1 · main · 2560 × 1440",
            "Screen 2 · 1920 × 1080",
            "All screens",
        ];
        for (which, texts) in [
            (Sheet::ViewerQuality, menu),
            (Sheet::ViewerDetails, details),
            (Sheet::ViewerScreens, screens),
        ] {
            let mut m = model(false, false);
            sheet(&mut m, which);
            let ClientStage::Live(viewing) = &m.client else {
                panic!("{which:?}: no live session");
            };
            let mut w = Window::new(true);
            w.viewing = viewing.clone();
            w.viewing.pictures = 0;
            w.viewing.size = (1280, 720);
            open_stream(
                which.stream().expect("a stream sheet"),
                &mut w.viewer,
                w.start,
            );
            for at in [0, 5000] {
                w.pass(ms(at), Vec::new());
                w.pass(ms(at), Vec::new());
                for text in texts {
                    assert!(w.has(text), "{which:?}, {at} ms: {text}: {:?}", w.texts());
                }
            }
        }
        for other in [Sheet::New, Sheet::StageLive, Sheet::LinkFilled] {
            assert_eq!(other.stream(), None);
        }
    }

    /// The preview draws in the theme its command line names (the settings
    /// page shows that one chosen), and its settings page shows made-up
    /// values: it reads no configuration and creates nothing.
    #[test]
    fn the_preview_draws_in_the_theme_it_was_given() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let paths = Paths::from_home(&home);
        for (theme, saved) in [
            (egui::Theme::Dark, tornect_core::config::Theme::Dark),
            (egui::Theme::Light, tornect_core::config::Theme::Light),
        ] {
            let mut preview = opts(true, Some(Page::Settings));
            preview.theme = theme;
            let start = start(&paths, &preview).unwrap();
            assert_eq!(start.model.settings.theme, saved);
            assert_eq!(start.model.settings.device_name, "Linux PC");
            assert!(!home.exists(), "{theme:?}: the preview created {home:?}");
        }
    }
}
