//! The grant wizard of Settings, Security (§B.8.7.1 ① to ⑦): it gives one
//! paired device unattended access. ① says what that means, the scam
//! line, this system's limits and what is kept and who learns what; its
//! Continue answers a pointer click only, armed after a second, with Cancel
//! first in the key order. ② lists the paired devices without access (one
//! without a completed attended session only with the waiver), ③ the
//! presets with their defaults, ④ the password: the generator's passphrase,
//! shown once and never selectable, or, only where the guard's preview says
//! the grant's reach stays 0 (decision M1-67), one of the person's own,
//! masked, never copied, at most one character beyond the policy and never
//! growing, its undo state cleared every frame. ⑤ sets the
//! grant's options over the preset's defaults, each by its own rule, and
//! shows the host-wide ones as they are; an option that makes the reach
//! non-zero takes an own password back to ④'s generator. ⑤a, where the
//! guard's account facts are not Linux's and ⑤ chose Control, offers the
//! administrator level, off in every preset, with its warning, or the guard's
//! refusal; on, it
//! takes ④ back to the generator with the new-grant line under it (on Linux
//! ⑤ says why the step is absent). ⑥ shows this
//! computer's readiness rows; a red one needs "Enable anyway". ⑦ sums it up,
//! and *Turn on* sends it as one operation, which the tokio side runs
//! through the guard; the wizard changes only on its answer. ④ and ⑦
//! complete by a primary pointer click only. Every password and passphrase
//! is dropped (wiped) on Cancel, Back, close and once sent. While this screen
//! is shared the wizard closes (the section shows the hidden card).

use std::time::{Duration, Instant};

use egui::{RichText, Ui};
use tornect_core::DeviceId;
use tornect_core::levels::{ADMINISTRATOR_WARNING, AccountFacts, Elevation};
use tornect_core::session_log::SessionMode;
use tornect_core::unattended::grant::{MAX_BLOCK_WINDOW_S, Preset};
use tornect_core::unattended::guard::NewlyReaching;
use tornect_core::unattended::ipc::GrantOptions;
use tornect_core::unattended::password::{self, PolicyError};
use zeroize::Zeroizing;

use super::super::super::backend::Secret;
use super::super::super::model::{
    Candidate, GrantRequest, Manager, ManagerOp, Model, NewPassword, PolicyInputs, WizardAnswer,
    WizardChoice,
};
use super::super::super::theme::{self, Face, Tokens};
use super::super::super::view::Action;
use super::super::super::widgets::{self, Button, Kind, Tone};
use super::{SettingsForm, line};

/// The Security section's button that opens the wizard (§B.8.7.1).
pub(in super::super) const OPEN: &str = "Turn on for a device…";

/// What unattended access is, at ①.
pub(in super::super) const EXPLANATION: &str = "Unattended access lets a paired device connect \
    to this computer with the password you set now, without anyone here accepting unless you \
    choose to be asked first.";

/// The scam step (§B.8.7.1 ①).
pub(in super::super) const SCAM: &str = "Did someone call and ask you to set this up? Hang up.";

/// This system's limits (§B.8.8), on Linux.
pub(in super::super) const LIMITS_LINUX: [&str; 2] = [
    "On GNOME, while this computer is locked, a session shows no picture and takes no input, and \
     it cannot be unlocked from another device. On other desktops this is not checked yet.",
    "At the login screen, before anyone signs in, there is nothing to connect to.",
];

/// This system's limits (§B.8.8), on Windows.
pub(in super::super) const LIMITS_WINDOWS: [&str; 2] = [
    "While this computer is locked or signed out, a session shows no picture and takes no \
     input, and it cannot be unlocked from another device: that needs a system service, \
     planned after this release.",
    "A session's clicks and keys do not reach programs that run as administrator or Windows' \
     prompts for an administrator, unless another device has administrator access here or this \
     account's settings make control administrator access. The other device is told when they \
     are out of its reach.",
];

/// What is kept and who learns what (§B.8.7.1 ①, as the operator approved
/// them).
pub(in super::super) const DISCLOSURES: [&str; 6] = [
    "This computer keeps, for each device you give access: when it last connected, how and for \
     how long, its failed attempts, and log lines of its attempts (repeated refusals are summed \
     into one line). That device keeps a line for each time it connected here, and may remember \
     the password, never for administrator access.",
    "Before it gives the password, that device can learn whether its access here is locked, \
     suspended or not yet active, and how long it must wait after this computer's clock went \
     back. With the password, it can also learn whether someone is signed in or using this \
     computer, whether another remote session is running, and when its next allowed time \
     starts.",
    "It learns how long you have to stop a connection, and whether you are asked first, only \
     when a connection is accepted.",
    "A device with control under My machines can unlock another device's access here by its ID, \
     and so learns whether that ID has access.",
    "The log keeps the name you give that device here: use a description of the device, such as \
     \"Office laptop\", not a person's name.",
    "If it remembers the password, anyone who can use that device can connect here as it until \
     you revoke it.",
];

/// ② with no device to offer.
pub(in super::super) const NO_DEVICE: &str =
    "Pair a device first: only a paired device can be given unattended access.";

/// Settings, Security with no device to offer because every paired device
/// already has unattended access.
pub(in super::super) const ALL_GRANTED: &str =
    "Every paired device here already has unattended access.";

/// The waiver of §B.8.6.1, for a device with no completed attended session.
pub(in super::super) const WAIVER: &str =
    "This device has not had a session here that you accepted. Give it unattended access anyway.";

/// The presets in the order ③ offers them, by their plan names.
pub(in super::super) const PRESETS: [(Preset, &str); 3] = [
    (Preset::MyMachines, "My machines"),
    (Preset::HelpingSomeone, "Helping someone"),
    (Preset::HeadlessBox, "Headless box"),
];

/// Under the generator's passphrase (§B.8.7.4).
pub(in super::super) const WRITE_IT_DOWN: &str = super::security::WRITE_IT_DOWN;

/// The generator's offline estimate (§B.8.2.2).
pub(in super::super) const GENERATED_ESTIMATE: &str = "Offline guessing estimate: about 450 \
    million years on one strong graphics card, if this computer's Tornect data were stolen.";

/// The secondary choice of ④, offered only where the reach stays 0.
pub(in super::super) const USE_MY_OWN: &str = "Use my own password";

/// Back to the generator from ④'s own password.
pub(in super::super) const USE_GENERATED: &str = "Use a generated password";

/// The hints of ④'s two fields.
pub(in super::super) const FIELD: &str = "Your password";

/// See [`FIELD`].
pub(in super::super) const AGAIN: &str = "Type it again";

/// The two entries of an own password differ.
pub(in super::super) const DIFFER: &str = "The two entries differ.";

/// The hard lock off (`hard_lock_after` 0), as §B.8.7.1 ⑤ warns of it.
pub(in super::super) const HARD_LOCK_OFF: &str = "With 0 the hard lock is off: guessing is then \
    limited only by the lifetime budget, at most 60 failed attempts until it is unlocked here or \
    from one of your devices with control under My machines, plus about 52 a year, at most 24 a \
    day (about 33 on the first day), and by the notifications.";

/// An expiry of "never" (§B.8.6.1).
pub(in super::super) const NEVER_WARNING: &str = "Access that never ends stays until you remove \
    it, also if that device is lost or you forget it.";

/// ⑤ for *Headless box* (the plan's statement for that preset, §B.8.7.1).
pub(in super::super) const HEADLESS_STATEMENT: &str = "With this preset a session can start the \
    moment the password is accepted, and anyone who turns this computer on gets its desktop as the \
    paired device would.";

/// The tick ⑤ needs for *Headless box* with no time to stop a connection,
/// before its Continue.
pub(in super::super) const I_UNDERSTAND: &str = "I understand";

/// Where ⑤ sends the host-wide options.
pub(in super::super) const HOST_WIDE: &str = "Set on the Security page for every device.";

/// ⑦, while unattended access is off: two dialogs follow.
pub(in super::super) const ASKS_TWICE: &str = "You are asked for your password once to give \
    access, and once more to turn unattended access on.";

/// ⑦, while a pause runs (§B.8.6.2); `<device>` stands for the pinned label.
pub(in super::super) const PAUSED_SUMMARY: &str =
    "Unattended access is paused: <device> can connect once the pause ends.";

/// Only a generated password will do now (decision M1-67): the guard's
/// preview at the commit found the reach non-zero before any dialog, or
/// `G_NEEDS_PASSWORD` after the dialog said a raise appeared while the
/// person was asked.
pub(in super::super) const NEEDS_GENERATED: &str = "Something changed on this computer: this \
    device now needs a new generated password. Nothing was saved.";

/// The commit of ⑦.
pub(in super::super) const TURN_ON: &str = "Turn on";

/// The manager's *Change password*, its row button and its commit.
pub(in super::super) const CHANGE_PASSWORD: &str = "Change password";

/// The manager's *Change mode*'s commits.
pub(in super::super) const TO_VIEW_ONLY: &str = "Change to View only";

/// See [`TO_VIEW_ONLY`].
pub(in super::super) const TO_CONTROL: &str = "Change to Control";

/// ④ while the guard's preview of the choice says only a generated password
/// will do (§B.8.7.1, decision M1-67); `<device>` stands for the device's
/// pinned label.
pub(in super::super) const GENERATED_ONLY: &str = "Control here can reach programs that run as \
    administrator, so <device> needs a generated password.";

/// Mode → Control where control reaches programs that run as administrator
/// (§B.8.7.1, decision M1-67); `<device>` stands for the grant's pinned
/// label.
pub(in super::super) const CONTROL_NEEDS_PASSWORD: &str = "Control here can reach programs that \
    run as administrator, so <device> needs a new password. The current password stops working \
    when you finish, also where it is remembered.";

/// Mode → Control where the guard's preview could not judge whether control
/// reaches programs that run as administrator (a new generated password all
/// the same); `<device>` stands for the grant's pinned label.
pub(in super::super) const CANNOT_TELL_NEEDS_PASSWORD: &str = "Tornect cannot tell now whether \
    control here reaches programs that run as administrator, so <device> needs a new password. \
    The current password stops working when you finish, also where it is remembered.";

/// ⑤a's switch (§B.8.7.1); `<device>` stands for the device's pinned label.
pub(in super::super) const ADMINISTRATOR_PROMPT: &str = "Let <device> also use programs that run \
    as administrator when it connects without asking";

/// Under ④'s passphrase for a new grant with the administrator level
/// (§B.8.7.1, decision M1-67); `<device>` stands for the pinned label.
pub(in super::super) const NEW_GRANT_LINE: &str = "An up-to-date Tornect on <device> does not \
    keep this password; type it in the Tornect window there each time.";

/// In ⑤a's place on Linux, where the step is absent (§B.8.7.1).
pub(in super::super) const LINUX_SENTENCE: &str = "On Linux, Tornect runs as you. An unattended \
    session can do what you can do without a password; when the system asks for a password, they \
    see that window and can type into it.";

/// The manager's raise of a grant to the administrator level, its row
/// button.
pub(in super::super) const RAISE: &str = "Give administrator access…";

/// Raising a grant to the administrator level (§B.8.7.1, decision M1-67);
/// `<device>` stands for the pinned label.
pub(in super::super) const RAISE_LINE: &str = "Administrator access needs a new password for \
    <device>. The current password stops working when you finish, also where it is remembered.";

/// Enabling a marked grant at the level (§B.8.7.1, decision M1-67);
/// `<device>` stands for the pinned label.
pub(in super::super) const RESTORE_LINE: &str = "Administrator access for <device> needs a new \
    password after a restore or an import. The old one stops working when you finish.";

/// The restore's end when its new password was set but *Enable* was refused
/// (§B.8.6.1); `<device>` stands for the pinned label.
pub(in super::super) const RESTORED_NOT_ENABLED: &str =
    "The new password for <device> is set. Its access is still disabled: use Enable on its row.";

/// The ⑤a offer's heading (§B.8.7.1); `<labels>` stands for the pinned
/// labels of the devices it names.
pub(in super::super) const OFFER_HEADING: &str = "These devices have control of this computer: \
    <labels>. From now on their control can reach programs that run as administrator here.";

/// The offer's tick (§B.8.7.1), ticked when the offer opens.
pub(in super::super) const GIVE_NEW: &str = "Give them new passwords now";

/// Unticked, the offer names only the devices whose password is marked
/// (§B.8.7.1, §B.8.6.1); `<labels>` stands for their pinned labels.
pub(in super::super) const UNTICKED_LINE: &str = "<labels> get view only until you give each \
    one a new password: their current passwords may be kept on those devices, were chosen, or \
    are older than this version of Tornect.";

/// After a round of the offer whose prompts did not all finish (§B.8.7.1,
/// §B.8.7.4); `<labels>` stands for the pinned labels.
pub(in super::super) const STILL_OLD: &str =
    "These devices still have their old password: <labels>.";

/// How long ①'s Continue waits, still, before a click counts (M1-50).
const ARM_AFTER: Duration = Duration::from_secs(1);

/// The ids of ④'s two fields, whose undo copies are dropped every frame.
const FIELD_IDS: [&str; 2] = ["wizard-password", "wizard-password-again"];

/// Room for a password of [`password::MAX_CHARS`] characters and one more
/// (a field takes no more: [`FIELD_CHARS`]), reserved before the first is
/// typed: a string that grows leaves its outgrown copies in freed memory,
/// unwiped.
const FIELD_ROOM: usize = FIELD_CHARS * 4;

/// The most a password field takes: one character more than the policy
/// allows, so that the meter can say so.
const FIELD_CHARS: usize = password::MAX_CHARS + 1;

/// The tick a red readiness row needs before ⑦ (§B.8.7.1 ⑥).
pub(in super::super) const ENABLE_ANYWAY: &str = "Enable anyway — it will not work until fixed";

/// The wizard's steps, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in super::super) enum Step {
    /// ① What it means, the scam line, the limits, the disclosures.
    Before,
    /// ② The paired device.
    Device,
    /// ③ The preset.
    Preset,
    /// ④ The password.
    Password,
    /// ⑤ The grant's options.
    Options,
    /// ⑤a The administrator level (not on Linux).
    Administrator,
    /// ⑥ This computer's readiness.
    Check,
    /// ⑦ What is given, and *Turn on*.
    Summary,
    /// The manager's *Change mode* of an existing grant.
    Mode,
    /// The manager's raise of a grant to the administrator level.
    Raise,
    /// The manager's *Enable* of a marked grant at the level: its new
    /// password first.
    Restore,
    /// ⑤a's offer of new passwords to the other control grants a change
    /// made reach the administrator level.
    Offer,
}

impl Step {
    /// The step's title.
    #[must_use]
    pub(in super::super) fn title(self) -> &'static str {
        match self {
            Self::Before => "Before you start",
            Self::Device => "Choose a device",
            Self::Preset => "Choose how it is used",
            Self::Password => "Password",
            Self::Options => "Options",
            Self::Administrator => "Administrator access",
            Self::Check => "Check this computer",
            Self::Summary => "Summary",
            Self::Mode => "Change mode",
            Self::Raise | Self::Offer => "Administrator access",
            Self::Restore => "Enable",
        }
    }
}

/// ⑤'s choices: the preset's defaults (§B.8.6.1) until changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in super::super) struct Options {
    /// Control or view only.
    pub(in super::super) mode: SessionMode,
    /// The access never ends (an explicit choice, with its warning).
    pub(in super::super) never: bool,
    /// Seconds to stop a connection.
    pub(in super::super) block_window_s: u8,
    /// Failed attempts in a row before the hard lock; 0: off (warned).
    pub(in super::super) hard_lock_after: u32,
    /// "Ask before starting".
    pub(in super::super) ask_before_start: bool,
    /// Pictures and input through Tor only.
    pub(in super::super) require_tor_only: bool,
    /// ⑤a: the administrator level (off in every preset).
    pub(in super::super) admin: bool,
}

impl Options {
    /// What `preset` sets.
    #[must_use]
    pub(in super::super) fn of(preset: Preset) -> Self {
        let d = preset.defaults();
        Self {
            mode: d.mode,
            never: false,
            block_window_s: d.block_window_s,
            hard_lock_after: d.hard_lock_after,
            ask_before_start: d.ask_before_start,
            require_tor_only: false,
            admin: false,
        }
    }
}

/// A change of an existing grant from the manager (§B.8.7.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in super::super) struct Changing {
    /// The grant's pinned label.
    pub(in super::super) label: String,
    /// The mode the new password comes with: control, where control reaches
    /// the administrator level; `None`: the password only.
    pub(in super::super) mode: Option<SessionMode>,
    /// *Change mode* to control asked the guard's preview.
    pub(in super::super) asked: bool,
    /// That preview could not judge whether control reaches the
    /// administrator level.
    pub(in super::super) unjudged: bool,
}

/// ⑤a's offer (§B.8.7.1, decision M1-67): one round of prompts over the
/// devices it names, then the devices left on their old password again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in super::super) struct Offer {
    /// This round's devices still to be asked, the first one asked now.
    pub(in super::super) queue: Vec<NewlyReaching>,
    /// This round's devices whose new password did not finish.
    pub(in super::super) left: Vec<NewlyReaching>,
    /// A round left these devices on their old password.
    pub(in super::super) again: bool,
    /// "Give them new passwords now".
    pub(in super::super) give: bool,
    /// The round's prompts run.
    pub(in super::super) asking: bool,
}

/// What the wizard remembers from pass to pass. Never printed: its
/// passwords are wiped when it is dropped.
pub(in super::super) struct Wizard {
    /// The step shown.
    pub(in super::super) step: Step,
    /// Since when ①'s Continue has been where it is, and where.
    armed: Option<(Instant, egui::Pos2)>,
    /// The device chosen at ②.
    pub(in super::super) device: Option<DeviceId>,
    /// ②'s waiver, for a device without a completed attended session.
    pub(in super::super) waive: bool,
    /// The preset chosen at ③.
    pub(in super::super) preset: Preset,
    /// ⑤'s choices.
    pub(in super::super) options: Options,
    /// ⑥'s "Enable anyway" for a red readiness row.
    pub(in super::super) enable_anyway: bool,
    /// ⑤'s "I understand" for *Headless box* with no time to stop a
    /// connection.
    pub(in super::super) understood: bool,
    /// The generator's passphrase of ④, drawn when ④ opens: shown there
    /// only, sent as generated.
    pub(in super::super) passphrase: Option<NewPassword>,
    /// ④'s own password was chosen.
    pub(in super::super) own: bool,
    /// ④'s own password as typed.
    pub(in super::super) typed: Zeroizing<String>,
    /// ④'s own password typed again.
    pub(in super::super) again: Zeroizing<String>,
    /// The press of *Turn on* waiting for its answer.
    pub(in super::super) attempt: Option<u64>,
    /// A change of an existing grant from the manager, in place of a new one.
    pub(in super::super) change: Option<Changing>,
    /// Something changed while the person was asked: from then on the
    /// password can only be generated.
    pub(in super::super) generated_only: bool,
    /// Why the last *Turn on* saved nothing.
    pub(in super::super) note: Option<&'static str>,
    /// ④'s passphrase was shown with the new-grant line under it.
    pub(in super::super) level_line: bool,
    /// ⑤a's offer, once a change made other control grants reach the level.
    pub(in super::super) offer: Option<Offer>,
    /// The restore's new password was set and *Enable* refused: the step
    /// ends with the sentence that says so.
    pub(in super::super) not_enabled: bool,
}

impl std::fmt::Debug for Wizard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wizard")
            .field("step", &self.step)
            .field("own", &self.own)
            .field("typed", &!self.typed.is_empty())
            .finish_non_exhaustive()
    }
}

impl Wizard {
    /// A wizard at ①.
    #[must_use]
    pub(in super::super) fn new() -> Self {
        Self {
            step: Step::Before,
            armed: None,
            device: None,
            waive: false,
            preset: Preset::MyMachines,
            options: Options::of(Preset::MyMachines),
            enable_anyway: false,
            understood: false,
            passphrase: None,
            own: false,
            typed: room(),
            again: room(),
            attempt: None,
            change: None,
            generated_only: false,
            note: None,
            level_line: false,
            offer: None,
            not_enabled: false,
        }
    }

    /// The manager's *Change password* of `device`'s grant, labelled
    /// `label`: ④ alone, with a new passphrase.
    #[must_use]
    pub(in super::super) fn change_password(device: DeviceId, label: String) -> Self {
        let mut w = Self::new();
        w.device = Some(device);
        w.change = Some(Changing {
            label,
            mode: None,
            asked: false,
            unjudged: false,
        });
        w.open_password();
        w
    }

    /// The manager's raise of `device`'s grant, labelled `label`, to the
    /// administrator level: a new passphrase, shown once the guard's preview
    /// of the raise says this computer can give the level.
    #[must_use]
    pub(in super::super) fn raise(device: DeviceId, label: String) -> Self {
        let mut w = Self::change_password(device, label);
        w.options.admin = true;
        w.generated_only = true;
        w.step = Step::Raise;
        w
    }

    /// The manager's *Enable* of `device`'s marked grant at the level,
    /// labelled `label`: a new passphrase first (§B.8.6.1).
    #[must_use]
    pub(in super::super) fn restore(device: DeviceId, label: String) -> Self {
        let mut w = Self::change_password(device, label);
        w.generated_only = true;
        w.step = Step::Restore;
        w
    }

    /// ⑤a's offer for the devices `reaching`, at its heading, ticked: every
    /// password of the change that led here is gone.
    fn open_offer(&mut self, reaching: Vec<NewlyReaching>) {
        self.drop_passwords();
        self.note = None;
        self.step = Step::Offer;
        self.offer = Some(Offer {
            queue: reaching,
            left: Vec::new(),
            again: false,
            give: true,
            asking: false,
        });
    }

    /// ⑤a's offer alone, for the devices `reaching`: the answer of a press
    /// whose wizard had closed (§B.8.7.1, decision M1-67).
    pub(in super::super) fn offer(reaching: Vec<NewlyReaching>) -> Self {
        let mut w = Self::new();
        w.open_offer(reaching);
        w
    }

    /// The answer to the offer's prompt for its first device (`done`: its
    /// new password is registered), or that prompt skipped: then the next
    /// device's prompt with a new passphrase, or, the round over, the devices
    /// left on their old password listed again. Whether none is left.
    fn offer_next(&mut self, done: bool) -> bool {
        let Some(offer) = self.offer.as_mut() else {
            return true;
        };
        if !offer.queue.is_empty() {
            let asked = offer.queue.remove(0);
            if !done {
                offer.left.push(asked);
            }
        }
        let prompt = if offer.queue.is_empty() {
            if offer.left.is_empty() {
                return true;
            }
            offer.queue = std::mem::take(&mut offer.left);
            offer.again = true;
            offer.give = true;
            offer.asking = false;
            false
        } else {
            true
        };
        self.passphrase = if prompt { generated() } else { None };
        false
    }

    /// After a refused answer: the same step again with a new passphrase
    /// (the raise and the restore), else ④.
    fn again(&mut self) {
        match self.step {
            Step::Raise | Step::Restore => {
                self.passphrase = generated();
                self.drop_own();
            }
            _ => self.open_password(),
        }
    }

    /// What a change from the manager registers, for the guard's preview.
    #[must_use]
    pub(in super::super) fn change_choice(&self) -> Option<WizardChoice> {
        self.change.as_ref().and_then(|_| self.choice())
    }

    /// The manager's *Change mode* of `device`'s grant, labelled `label`.
    #[must_use]
    pub(in super::super) fn change_mode(device: DeviceId, label: String) -> Self {
        let mut w = Self::change_password(device, label);
        w.drop_passwords();
        w.step = Step::Mode;
        w
    }

    /// What ②, ③ and ⑤ chose: every option goes into the one registration.
    /// For a change from the manager: the options that change nothing (the
    /// grant keeps its preset, which a registration of an existing grant
    /// reads from the store), but the mode where control needs the password.
    fn choice(&self) -> Option<WizardChoice> {
        if let Some(change) = &self.change {
            return Some(WizardChoice {
                device: self.device?,
                preset: Preset::MyMachines,
                options: GrantOptions {
                    mode: change.mode,
                    elevation: self.options.admin.then_some(Elevation::Admin),
                    ..GrantOptions::default()
                },
            });
        }
        let o = self.options;
        Some(WizardChoice {
            device: self.device?,
            preset: self.preset,
            options: GrantOptions {
                mode: Some(o.mode),
                expires_at: o.never.then_some(0),
                block_window_s: Some(o.block_window_s),
                ask_before_start: Some(o.ask_before_start),
                // Not offered (OPEN until the host carries them out): saved
                // as off, every preset's default.
                require_absent: Some(false),
                require_tor_only: Some(o.require_tor_only),
                lock_on_disconnect: Some(false),
                hard_lock_after: Some(o.hard_lock_after),
                waive_attended_precondition: self.waive,
                elevation: o.admin.then_some(Elevation::Admin),
                ..GrantOptions::default()
            },
        })
    }

    /// Go to ④ with a new passphrase and no own password: every earlier
    /// one is wiped.
    fn open_password(&mut self) {
        self.step = Step::Password;
        self.passphrase = generated();
        self.level_line = false;
        self.drop_own();
    }

    /// ②'s, ③'s and ⑤'s choice with the administrator level on: what ⑤a
    /// asks the guard's preview of, to learn whether this computer can give
    /// it.
    fn with_level(&self) -> Option<WizardChoice> {
        let mut choice = self.choice()?;
        choice.options.elevation = Some(Elevation::Admin);
        Some(choice)
    }

    /// The own password and its copy, wiped.
    fn drop_own(&mut self) {
        self.own = false;
        self.typed = room();
        self.again = room();
    }

    /// Leave ④ or ⑦ backwards: every password goes.
    fn drop_passwords(&mut self) {
        self.passphrase = None;
        self.drop_own();
    }
}

/// An empty password field with room for the longest password.
fn room() -> Zeroizing<String> {
    Zeroizing::new(String::with_capacity(FIELD_ROOM))
}

/// The generator's passphrase (§B.8.7.1 ④): five words of EFF's long list,
/// as a login reads them (§B.8.7.2). The only place that builds
/// [`NewPassword::Generated`].
fn generated() -> Option<NewPassword> {
    let drawn = password::generate_passphrase().ok()?;
    Some(NewPassword::Generated(Secret(password::normalize(&drawn))))
}

/// The wizard, drawn in place of the Security section's body; `manager` is
/// the guard's view the section shows.
pub(in super::super) fn draw(
    ui: &mut Ui,
    model: &Model,
    manager: &Manager,
    form: &mut SettingsForm,
    actions: &mut Vec<Action>,
) {
    let t = theme::tokens(ui.ctx());
    let Some(w) = form.wizard.as_mut() else {
        return;
    };
    // The answer to this wizard's press of Turn on.
    if let (Some(attempt), Some((answered, answer))) = (w.attempt, model.wizard.answer)
        && attempt == answered
    {
        w.attempt = None;
        if w.step == Step::Offer {
            // An offer's prompt: the next device, or the round's end.
            if let WizardAnswer::Refused(why) = answer {
                w.note = Some(why);
            }
            if w.offer_next(answer == WizardAnswer::Done) {
                form.wizard = None;
                return;
            }
        } else {
            match answer {
                WizardAnswer::Done if !model.wizard.reaching.is_empty() => {
                    // Other control grants now reach the level: ⑤a's offer.
                    w.open_offer(model.wizard.reaching.clone());
                }
                WizardAnswer::Done => {
                    form.wizard = None;
                    return;
                }
                WizardAnswer::NeedsGenerated => {
                    w.generated_only = true;
                    w.note = Some(NEEDS_GENERATED);
                    w.again();
                }
                WizardAnswer::Refused(why) => {
                    w.note = Some(why);
                    w.again();
                }
                // The restore's new password is set: no other is asked.
                WizardAnswer::SetNotEnabled => {
                    w.drop_passwords();
                    w.not_enabled = true;
                }
            }
        }
    }
    ui.add_space(4.0);
    let title = match (&w.change, w.step) {
        (Some(_), Step::Password) => CHANGE_PASSWORD,
        _ => w.step.title(),
    };
    ui.label(
        RichText::new(title)
            .font(theme::font(ui.ctx(), Face::Semibold, 17.0))
            .color(t.text_primary),
    );
    ui.add_space(6.0);
    let mut close = false;
    match w.step {
        Step::Before => before(ui, t, w, &mut close),
        Step::Device => device(ui, t, model, w, &mut close),
        Step::Preset => preset(ui, t, w, &mut close, actions),
        Step::Password => {
            let attempt = form.attempts + 1;
            if password_step(ui, t, model, w, &mut close, attempt, actions) {
                form.attempts = attempt;
            }
        }
        Step::Mode => mode_step(ui, t, model, w, &mut close, actions),
        Step::Raise | Step::Restore => {
            let attempt = form.attempts + 1;
            if level_password(ui, t, model, w, &mut close, attempt, actions) {
                form.attempts = attempt;
            }
        }
        Step::Offer => {
            let attempt = form.attempts + 1;
            if offer_step(ui, t, w, &mut close, attempt, actions) {
                form.attempts = attempt;
            }
        }
        Step::Options => options(ui, t, model, manager, w, &mut close, actions),
        Step::Administrator => administrator(ui, t, model, w, &mut close, actions),
        Step::Check => check(ui, t, manager, w, &mut close),
        Step::Summary => {
            let attempt = form.attempts + 1;
            if summary(ui, t, model, manager, w, &mut close, attempt, actions) {
                form.attempts = attempt;
            }
        }
    }
    if close {
        form.wizard = None;
    }
    if form.wizard.as_ref().is_none_or(|w| !w.own) {
        forget_fields(ui.ctx(), true);
    }
}

/// The undo copies of ④'s fields, dropped: every frame they are drawn, and
/// their whole state once they are not (`gone`).
pub(in super::super) fn forget_fields(ctx: &egui::Context, gone: bool) {
    for id in FIELD_IDS.map(egui::Id::new) {
        if gone {
            ctx.data_mut(|d| d.remove::<egui::text_edit::TextEditState>(id));
        } else if let Some(mut state) = egui::text_edit::TextEditState::load(ctx, id) {
            state.clear_undoer();
            state.store(ctx, id);
        }
    }
}

/// A forward button of a trust step: answered by a primary pointer click
/// only, never in the Tab order (`Sense::CLICK`, not focusable), so Enter,
/// Space or Tab then Enter never presses it (M-UI-3).
fn pointer_only(ui: &mut Ui, label: &str, enabled: bool) -> bool {
    ui.add_enabled(
        enabled,
        egui::Button::new(RichText::new(label).strong()).sense(egui::Sense::CLICK),
    )
    .clicked_by(egui::PointerButton::Primary)
}

/// Whether ①'s Continue may answer now: once it has been still for
/// [`ARM_AFTER`] (it arms again when it moves).
fn armed(ui: &Ui, w: &mut Wizard) -> bool {
    let at = ui.cursor().min;
    let now = Instant::now();
    let since = match w.armed {
        Some((since, was)) if was.distance(at) <= 1.0 => since,
        _ => now,
    };
    w.armed = Some((since, at));
    let still = now.saturating_duration_since(since);
    if still < ARM_AFTER {
        ui.ctx().request_repaint_after(ARM_AFTER - still);
        return false;
    }
    true
}

/// Cancel, first in the key order of every step.
fn cancel(ui: &mut Ui, enabled: bool, close: &mut bool) {
    if Button::new(Kind::Secondary, "Cancel")
        .small()
        .enabled(enabled)
        .show(ui)
        .clicked()
    {
        *close = true;
    }
}

/// ①.
fn before(ui: &mut Ui, t: &Tokens, w: &mut Wizard, close: &mut bool) {
    line(ui, EXPLANATION, t.text_primary);
    ui.add_space(8.0);
    ui.label(
        RichText::new(SCAM)
            .font(theme::font(ui.ctx(), Face::Semibold, 14.0))
            .color(t.warn),
    );
    ui.add_space(8.0);
    let limits = if cfg!(windows) {
        LIMITS_WINDOWS
    } else {
        LIMITS_LINUX
    };
    for limit in limits {
        line(ui, limit, t.text_secondary);
    }
    ui.add_space(8.0);
    for disclosure in DISCLOSURES {
        line(ui, disclosure, t.text_secondary);
        ui.add_space(4.0);
    }
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        cancel(ui, true, close);
        let ready = armed(ui, w);
        if pointer_only(ui, "Continue", ready) && ready {
            w.step = Step::Device;
        }
    });
}

/// ②: the paired devices without unattended access, as the tokio side read
/// them when the wizard opened.
fn device(ui: &mut Ui, t: &Tokens, model: &Model, w: &mut Wizard, close: &mut bool) {
    let Some(devices) = &model.wizard.devices else {
        ui.spinner();
        ui.horizontal(|ui| cancel(ui, true, close));
        return;
    };
    if devices.is_empty() {
        line(ui, NO_DEVICE, t.text_secondary);
    }
    for c in devices {
        ui.radio_value(&mut w.device, Some(c.device), candidate_line(c));
    }
    let chosen = devices.iter().find(|c| Some(c.device) == w.device);
    if chosen.is_none() {
        w.device = None;
    }
    let needs_waiver = chosen.is_some_and(|c| !c.attended);
    if needs_waiver {
        ui.add_space(6.0);
        ui.checkbox(&mut w.waive, WAIVER);
    } else {
        w.waive = false;
    }
    ui.add_space(10.0);
    ui.horizontal(|ui| {
        cancel(ui, true, close);
        if Button::new(Kind::Secondary, "Back")
            .small()
            .show(ui)
            .clicked()
        {
            w.step = Step::Before;
        }
        let ready = chosen.is_some() && (!needs_waiver || w.waive);
        if Button::new(Kind::Primary, "Continue")
            .small()
            .enabled(ready)
            .show(ui)
            .clicked()
            && ready
        {
            w.step = Step::Preset;
        }
    });
}

/// A device as ② names it: its pinned label and its device words.
#[must_use]
pub(in super::super) fn candidate_line(c: &Candidate) -> String {
    match c.words {
        Some(words) => format!("{} · device words: {}", c.label, words.shown()),
        None => c.label.clone(),
    }
}

/// ③: the presets with their defaults; Continue asks the guard's preview of
/// the choice and opens ④ with a new passphrase.
fn preset(ui: &mut Ui, t: &Tokens, w: &mut Wizard, close: &mut bool, actions: &mut Vec<Action>) {
    for (preset, name) in PRESETS {
        ui.radio_value(&mut w.preset, preset, name);
        line(ui, &preset_defaults(preset), t.text_secondary);
        ui.add_space(4.0);
    }
    ui.add_space(10.0);
    ui.horizontal(|ui| {
        cancel(ui, true, close);
        if Button::new(Kind::Secondary, "Back")
            .small()
            .show(ui)
            .clicked()
        {
            w.step = Step::Device;
        }
        if Button::new(Kind::Primary, "Continue")
            .small()
            .show(ui)
            .clicked()
        {
            // ⑤ starts from this preset's defaults.
            w.options = Options::of(w.preset);
            if let Some(choice) = w.choice() {
                actions.push(Action::Manager(ManagerOp::Preview(Box::new(choice))));
                w.note = None;
                w.open_password();
            }
        }
    });
}

/// What a preset sets, from its own defaults (§B.8.6.1).
#[must_use]
pub(in super::super) fn preset_defaults(preset: Preset) -> String {
    let d = preset.defaults();
    let mut parts = vec![match d.mode {
        SessionMode::Control => "Control".to_owned(),
        SessionMode::ViewOnly => "View only".to_owned(),
    }];
    parts.push(match d.block_window_s {
        0 => "no time to stop a connection".to_owned(),
        s => format!("{s} s to stop a connection"),
    });
    if d.ask_before_start {
        parts.push("asks you before starting".to_owned());
    }
    if d.active_from_delay_s > 0 {
        parts.push(format!(
            "starts working {} hours after it is given",
            d.active_from_delay_s / 3600
        ));
    }
    if let Some(span) = d.expiry_span_s {
        let days = span / 86_400;
        parts.push(if d.auto_renew {
            format!("ends after {days} days without use")
        } else {
            format!("ends after {days} days")
        });
    }
    if let Some(max) = d.max_session_secs {
        parts.push(format!("sessions of up to {} hours", max / 3600));
    }
    if d.keep_awake {
        parts.push("keeps this computer awake".to_owned());
    }
    parts.join(" · ")
}

/// ⑤'s choices as ⑦ sums them up, with the preset's defaults that ⑤ does not
/// change, in the words of the presets' lines.
#[must_use]
pub(in super::super) fn options_line(preset: Preset, o: &Options) -> String {
    let d = preset.defaults();
    let mut parts = vec![match o.mode {
        SessionMode::Control => "Control".to_owned(),
        SessionMode::ViewOnly => "View only".to_owned(),
    }];
    parts.push(match o.block_window_s {
        0 => "no time to stop a connection".to_owned(),
        s => format!("{s} s to stop a connection"),
    });
    if o.ask_before_start {
        parts.push("asks you before starting".to_owned());
    }
    if d.active_from_delay_s > 0 {
        parts.push(format!(
            "starts working {} hours after it is given",
            d.active_from_delay_s / 3600
        ));
    }
    if o.never {
        parts.push("never ends".to_owned());
    } else if let Some(span) = d.expiry_span_s {
        let days = span / 86_400;
        parts.push(if d.auto_renew {
            format!("ends after {days} days without use")
        } else {
            format!("ends after {days} days")
        });
    }
    if let Some(max) = d.max_session_secs {
        parts.push(format!("sessions of up to {} hours", max / 3600));
    }
    if d.keep_awake {
        parts.push("keeps this computer awake".to_owned());
    }
    parts.push(match o.hard_lock_after {
        0 => "no hard lock after failed attempts in a row".to_owned(),
        n => format!("hard lock after {n} failed attempts in a row"),
    });
    if o.require_tor_only {
        parts.push("pictures and input through Tor only".to_owned());
    }
    if o.admin {
        parts.push("administrator access".to_owned());
    }
    parts.join(" · ")
}

/// Whether ④ may offer an own password for `w`'s choice: only once the
/// guard's preview of exactly this choice said the reach stays 0, and never
/// after a raise appeared (fail closed: no answer, no own password).
fn may_use_own(model: &Model, w: &Wizard) -> bool {
    !w.generated_only
        && w.choice().is_some_and(|choice| {
            model
                .wizard
                .preview
                .as_ref()
                .is_some_and(|(judged, generated_only)| {
                    *judged == choice && *generated_only == Some(false)
                })
        })
}

/// ④: the generator's passphrase, or the person's own password where the
/// reach stays 0. For a change from the manager ④ is all: its commit sends
/// the new password as press `attempt`; whether it was pressed.
fn password_step(
    ui: &mut Ui,
    t: &Tokens,
    model: &Model,
    w: &mut Wizard,
    close: &mut bool,
    attempt: u64,
    actions: &mut Vec<Action>,
) -> bool {
    if let Some(note) = w.note {
        line(ui, note, t.danger_text);
        ui.add_space(6.0);
    }
    if let Some(Changing {
        label,
        mode: Some(_),
        unjudged,
        ..
    }) = &w.change
    {
        let needs = if *unjudged {
            CANNOT_TELL_NEEDS_PASSWORD
        } else {
            CONTROL_NEEDS_PASSWORD
        };
        line(ui, &needs.replace("<device>", label), t.text_primary);
        ui.add_space(6.0);
    }
    let may_own = may_use_own(model, w);
    if !may_own && w.own {
        // The reach became non-zero: the own password goes, a new passphrase
        // comes.
        w.open_password();
    }
    let mut ready = false;
    if w.own {
        let policy = model.wizard.policy.as_ref();
        for (id, (text, hint)) in FIELD_IDS
            .into_iter()
            .zip([(&mut w.typed, FIELD), (&mut w.again, AGAIN)])
        {
            let field = ui.add(
                egui::TextEdit::singleline(&mut **text)
                    .id(egui::Id::new(id))
                    .password(true)
                    .char_limit(FIELD_CHARS)
                    .hint_text(hint)
                    .desired_width(300.0),
            );
            field.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::TextEdit, true, hint));
        }
        forget_fields(ui.ctx(), false);
        let (ok, lines) = meter(&w.typed, &w.again, policy);
        for (good, text) in lines {
            line(ui, &text, if good { t.text_secondary } else { t.warn });
        }
        ready = ok;
        if Button::new(Kind::Ghost, USE_GENERATED)
            .small()
            .show(ui)
            .clicked()
        {
            w.open_password();
        }
    } else if let Some(phrase) = &w.passphrase {
        // Why there is no own password, once the guard's preview of exactly
        // this choice said so (a change of mode says it in its own line).
        let changes_mode = w.change.as_ref().is_some_and(|c| c.mode.is_some());
        let generated_only = w.choice().is_some_and(|choice| {
            model
                .wizard
                .preview
                .as_ref()
                .is_some_and(|(judged, only)| *judged == choice && *only == Some(true))
        });
        if generated_only && !changes_mode {
            line(
                ui,
                &GENERATED_ONLY.replace("<device>", &label_of(model, w)),
                t.text_primary,
            );
        }
        ui.add(
            egui::Label::new(
                RichText::new(phrase.secret().0.as_str())
                    .font(theme::font(ui.ctx(), Face::Mono, 20.0))
                    .color(t.text_primary),
            )
            .selectable(false),
        );
        ui.add_space(4.0);
        line(ui, WRITE_IT_DOWN, t.warn);
        if w.options.admin && w.change.is_none() {
            line(
                ui,
                &NEW_GRANT_LINE.replace("<device>", &label_of(model, w)),
                t.text_primary,
            );
            w.level_line = true;
        }
        line(ui, GENERATED_ESTIMATE, t.text_secondary);
        ready = true;
        if may_own
            && Button::new(Kind::Ghost, USE_MY_OWN)
                .small()
                .show(ui)
                .clicked()
        {
            w.passphrase = None;
            w.own = true;
        }
    }
    let waiting = w.attempt.is_some();
    if waiting {
        ui.spinner();
    }
    ui.add_space(10.0);
    let mut pressed = false;
    ui.horizontal(|ui| {
        cancel(ui, !waiting, close);
        if w.change.is_some() {
            // ④ alone: its commit, pointer only.
            let ready = ready && !waiting;
            if pointer_only(ui, CHANGE_PASSWORD, ready) && ready {
                pressed = send_change(w, attempt, actions);
            }
            return;
        }
        if Button::new(Kind::Secondary, "Back")
            .small()
            .show(ui)
            .clicked()
        {
            w.drop_passwords();
            w.step = Step::Preset;
        }
        if pointer_only(ui, "Continue", ready) && ready {
            w.note = None;
            w.step = Step::Options;
        }
    });
    pressed
}

/// Send the manager's change with ④'s password as press `attempt`: the
/// wizard keeps no copy; whether it was sent.
fn send_change(w: &mut Wizard, attempt: u64, actions: &mut Vec<Action>) -> bool {
    let new = if w.own {
        Some(NewPassword::Chosen(Secret(password::normalize(&w.typed))))
    } else {
        w.passphrase.take()
    };
    let (Some(choice), Some(password)) = (w.choice(), new) else {
        return false;
    };
    actions.push(Action::Manager(ManagerOp::ChangePassword(Box::new(
        GrantRequest {
            attempt,
            choice,
            password,
        },
    ))));
    w.drop_passwords();
    w.note = None;
    w.attempt = Some(attempt);
    true
}

/// The manager's *Change mode* (§B.8.7.3): to view only, one operation that
/// narrows; to control, the guard's preview first: where control reaches the
/// administrator level, ④ with the plan's sentence and a generated password
/// in one registration; otherwise one operation that widens (it asks for the
/// password).
fn mode_step(
    ui: &mut Ui,
    t: &Tokens,
    model: &Model,
    w: &mut Wizard,
    close: &mut bool,
    actions: &mut Vec<Action>,
) {
    let (Some(device), Some(change)) = (w.device, w.change.clone()) else {
        *close = true;
        return;
    };
    let now = model
        .wizard
        .modes
        .iter()
        .find(|(d, _)| *d == device)
        .map(|(_, mode)| *mode);
    let to_control = WizardChoice {
        device,
        preset: Preset::MyMachines,
        options: GrantOptions {
            mode: Some(SessionMode::Control),
            ..GrantOptions::default()
        },
    };
    let raises = model
        .wizard
        .raises
        .as_ref()
        .filter(|(c, _)| *c == to_control)
        .map(|(_, r)| *r);
    let named = match now {
        Some(SessionMode::Control) => "Control",
        Some(SessionMode::ViewOnly) => "View only",
        None => "…",
    };
    line(ui, &format!("{}: {named}", change.label), t.text_primary);
    ui.add_space(10.0);
    ui.horizontal(|ui| {
        cancel(ui, true, close);
        match now {
            Some(SessionMode::Control) => {
                if Button::new(Kind::Primary, TO_VIEW_ONLY)
                    .small()
                    .show(ui)
                    .clicked()
                {
                    actions.push(Action::Manager(ManagerOp::SetMode(
                        device,
                        SessionMode::ViewOnly,
                    )));
                    *close = true;
                }
            }
            Some(SessionMode::ViewOnly) if !change.asked => {
                if Button::new(Kind::Primary, "Continue")
                    .small()
                    .show(ui)
                    .clicked()
                {
                    actions.push(Action::Manager(ManagerOp::Preview(Box::new(
                        to_control.clone(),
                    ))));
                    if let Some(c) = w.change.as_mut() {
                        c.asked = true;
                    }
                }
            }
            Some(SessionMode::ViewOnly) => match raises {
                // Not judged yet.
                None => {
                    ui.spinner();
                }
                // Control raises the reach (or it could not be judged):
                // only with a new generated password.
                Some(raised @ (Some(true) | None)) => {
                    if let Some(c) = w.change.as_mut() {
                        c.mode = Some(SessionMode::Control);
                        c.unjudged = raised.is_none();
                    }
                    w.generated_only = true;
                    w.open_password();
                }
                Some(Some(false)) => {
                    if pointer_only(ui, TO_CONTROL, true) {
                        actions.push(Action::Manager(ManagerOp::SetMode(
                            device,
                            SessionMode::Control,
                        )));
                        *close = true;
                    }
                }
            },
            None => {}
        }
    });
}

/// The manager's raise to the administrator level and the restore of a
/// marked grant at it (§B.8.7.1, decision M1-67): the plan's lines (the
/// raise: ⑤a's warning once the guard's preview has judged the level, its
/// sentence, then the new-grant line), a generated passphrase
/// shown once, Cancel first and Continue, which answers a primary pointer
/// click only, once the passphrase is shown, and sends it as press
/// `attempt` in one registration (the restore: then *Enable*). The raise
/// waits for the guard's preview and shows its refusal where this computer
/// cannot give the level. Whether Continue was pressed.
fn level_password(
    ui: &mut Ui,
    t: &Tokens,
    model: &Model,
    w: &mut Wizard,
    close: &mut bool,
    attempt: u64,
    actions: &mut Vec<Action>,
) -> bool {
    let restore = w.step == Step::Restore;
    let Some(choice) = w.choice() else {
        *close = true;
        return false;
    };
    if let Some(note) = w.note {
        line(ui, note, t.danger_text);
        ui.add_space(6.0);
    }
    let label = label_of(model, w);
    if w.not_enabled {
        line(
            ui,
            &RESTORED_NOT_ENABLED.replace("<device>", &label),
            t.text_primary,
        );
        ui.add_space(10.0);
        ui.horizontal(|ui| cancel(ui, true, close));
        return false;
    }
    let refused = model
        .wizard
        .level_refused
        .as_ref()
        .filter(|(c, _)| !restore && *c == choice)
        .map(|(_, why)| *why);
    let judged = restore
        || model
            .wizard
            .preview
            .as_ref()
            .is_some_and(|(c, _)| *c == choice);
    let mut shown = false;
    if let Some(why) = refused {
        line(ui, why, t.text_primary);
    } else if !judged {
        ui.spinner();
    } else if let Some(phrase) = &w.passphrase {
        if restore {
            line(
                ui,
                &RESTORE_LINE.replace("<device>", &label),
                t.text_primary,
            );
        } else {
            // What ⑤a says of the level, said where the level is given.
            line(
                ui,
                &ADMINISTRATOR_WARNING.replace("<device>", &label),
                t.warn,
            );
            line(ui, &RAISE_LINE.replace("<device>", &label), t.text_primary);
            line(
                ui,
                &NEW_GRANT_LINE.replace("<device>", &label),
                t.text_primary,
            );
        }
        ui.add_space(6.0);
        ui.add(
            egui::Label::new(
                RichText::new(phrase.secret().0.as_str())
                    .font(theme::font(ui.ctx(), Face::Mono, 20.0))
                    .color(t.text_primary),
            )
            .selectable(false),
        );
        ui.add_space(4.0);
        line(ui, WRITE_IT_DOWN, t.warn);
        shown = true;
    }
    let waiting = w.attempt.is_some();
    if waiting {
        ui.spinner();
    }
    ui.add_space(10.0);
    let mut pressed = false;
    ui.horizontal(|ui| {
        cancel(ui, !waiting, close);
        if refused.is_some() {
            return;
        }
        let ready = shown && !waiting;
        if pointer_only(ui, "Continue", ready)
            && ready
            && let Some(password) = w.passphrase.take()
        {
            let request = Box::new(GrantRequest {
                attempt,
                choice: choice.clone(),
                password,
            });
            actions.push(Action::Manager(if restore {
                ManagerOp::Restore(request)
            } else {
                ManagerOp::ChangePassword(request)
            }));
            w.note = None;
            w.attempt = Some(attempt);
            pressed = true;
        }
    });
    pressed
}

/// The pinned labels of `devices`, as the offer's lines name them.
fn labels(devices: &[NewlyReaching]) -> String {
    devices
        .iter()
        .map(|d| d.label.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// ⑤a's offer (§B.8.7.1, decision M1-67): the heading with the devices'
/// pinned labels (after a round that left some on their old password, the
/// command line's "These devices still have their old password: …"), "Give
/// them new passwords now" ticked; unticked, the line naming only the
/// devices whose password is marked (none marked: no line), and Continue
/// closes, the marks applying; ticked, Continue asks for each device in
/// turn: a new generated passphrase shown once, and *Change password*,
/// which answers a primary pointer click only and sends it as press
/// `attempt`, its own registration and dialog; Cancel there leaves that
/// device on its old password. Whether a prompt was pressed.
fn offer_step(
    ui: &mut Ui,
    t: &Tokens,
    w: &mut Wizard,
    close: &mut bool,
    attempt: u64,
    actions: &mut Vec<Action>,
) -> bool {
    let Some(offer) = w.offer.clone() else {
        *close = true;
        return false;
    };
    if let Some(note) = w.note {
        line(ui, note, t.danger_text);
        ui.add_space(6.0);
    }
    if !offer.asking {
        let heading = if offer.again {
            STILL_OLD
        } else {
            OFFER_HEADING
        };
        line(
            ui,
            &heading.replace("<labels>", &labels(&offer.queue)),
            t.text_primary,
        );
        ui.add_space(6.0);
        let mut give = offer.give;
        ui.checkbox(&mut give, GIVE_NEW);
        let marked: Vec<NewlyReaching> = offer.queue.iter().filter(|d| d.marked).cloned().collect();
        if !give && !marked.is_empty() {
            line(
                ui,
                &UNTICKED_LINE.replace("<labels>", &labels(&marked)),
                t.warn,
            );
        }
        ui.add_space(10.0);
        let mut next = false;
        ui.horizontal(|ui| {
            next = pointer_only(ui, "Continue", true);
        });
        if let Some(o) = w.offer.as_mut() {
            o.give = give;
        }
        if next {
            w.note = None;
            if give {
                if let Some(o) = w.offer.as_mut() {
                    o.asking = true;
                }
                w.passphrase = generated();
            } else {
                *close = true;
            }
        }
        return false;
    }
    let Some(device) = offer.queue.first() else {
        *close = true;
        return false;
    };
    ui.label(
        RichText::new(format!("New password for {}", device.label))
            .font(theme::font(ui.ctx(), Face::Semibold, 15.0))
            .color(t.text_primary),
    );
    if let Some(phrase) = &w.passphrase {
        ui.add(
            egui::Label::new(
                RichText::new(phrase.secret().0.as_str())
                    .font(theme::font(ui.ctx(), Face::Mono, 20.0))
                    .color(t.text_primary),
            )
            .selectable(false),
        );
        ui.add_space(4.0);
        line(ui, WRITE_IT_DOWN, t.warn);
    }
    let waiting = w.attempt.is_some();
    if waiting {
        ui.spinner();
    }
    ui.add_space(10.0);
    let mut pressed = false;
    let mut skip = false;
    ui.horizontal(|ui| {
        skip = Button::new(Kind::Secondary, "Cancel")
            .small()
            .enabled(!waiting)
            .show(ui)
            .clicked()
            && !waiting;
        let ready = !waiting && w.passphrase.is_some();
        if pointer_only(ui, CHANGE_PASSWORD, ready)
            && ready
            && let Some(password) = w.passphrase.take()
        {
            actions.push(Action::Manager(ManagerOp::ChangePassword(Box::new(
                GrantRequest {
                    attempt,
                    choice: WizardChoice {
                        device: device.device,
                        preset: Preset::MyMachines,
                        options: GrantOptions::default(),
                    },
                    password,
                },
            ))));
            w.attempt = Some(attempt);
            pressed = true;
        }
    });
    if skip && w.offer_next(false) {
        *close = true;
    }
    pressed
}

/// ⑤: the grant's options over the preset's defaults, each by its rule
/// (§B.8.7.1 ⑤, §B.8.6.1); the host-wide ones as they are, set on the
/// Security page. Continue asks the guard's preview of the choice again (an
/// option can make the reach non-zero) and opens ⑦.
fn options(
    ui: &mut Ui,
    t: &Tokens,
    model: &Model,
    manager: &Manager,
    w: &mut Wizard,
    close: &mut bool,
    actions: &mut Vec<Action>,
) {
    let d = w.preset.defaults();
    let file_keystore = model
        .wizard
        .policy
        .as_ref()
        .is_none_or(|p| p.min_score >= password::MIN_SCORE_FILE_KEYSTORE);
    // ⑤a for control only: the administrator level is a level of control.
    let level_step = level_step(model) && w.options.mode == SessionMode::Control;
    if !level_step {
        w.options.admin = false;
    }
    let o = &mut w.options;
    widgets::section_header(ui, "Mode");
    ui.radio_value(&mut o.mode, SessionMode::Control, "Control");
    ui.radio_value(&mut o.mode, SessionMode::ViewOnly, "View only");
    ui.add_space(8.0);
    widgets::section_header(ui, "Ends");
    let lasts = match (d.expiry_span_s, d.auto_renew) {
        (Some(span), true) => format!("After {} days without use", span / 86_400),
        (Some(span), false) => format!("After {} days", span / 86_400),
        (None, _) => "Never".to_owned(),
    };
    ui.radio_value(&mut o.never, false, lasts);
    // "Never" is refused on a file keystore and where the preset caps the
    // expiry (§B.8.6.1, T3b): not offered there.
    if d.expiry_cap_s.is_none() && !file_keystore && d.expiry_span_s.is_some() {
        ui.radio_value(&mut o.never, true, "Never");
        if o.never {
            line(ui, NEVER_WARNING, t.warn);
        }
    } else {
        o.never = false;
    }
    ui.add_space(8.0);
    widgets::section_header(ui, "Time to stop a connection");
    // The preset's bounds (Helping someone: at least 5 s).
    o.block_window_s = o
        .block_window_s
        .clamp(d.min_block_window_s, MAX_BLOCK_WINDOW_S);
    ui.add(
        egui::Slider::new(
            &mut o.block_window_s,
            d.min_block_window_s..=MAX_BLOCK_WINDOW_S,
        )
        .suffix(" s"),
    );
    // Headless box: the plan's statement, and no time to stop a connection
    // only with the person's acknowledgement.
    let headless = w.preset == Preset::HeadlessBox;
    let acknowledge = headless && o.block_window_s == 0;
    if headless {
        line(ui, HEADLESS_STATEMENT, t.warn);
    }
    if acknowledge {
        ui.checkbox(&mut w.understood, I_UNDERSTAND);
    } else {
        w.understood = false;
    }
    ui.add_space(8.0);
    widgets::section_header(ui, "Hard lock after failed attempts in a row");
    // Below the lifetime budget: at the budget the lock in a row would be as
    // off as at 0, without the warning that 0 shows.
    ui.add(egui::Slider::new(
        &mut o.hard_lock_after,
        0..=tornect_core::unattended::grant::LIFETIME_BUDGET - 1,
    ));
    if o.hard_lock_after == 0 {
        line(ui, HARD_LOCK_OFF, t.warn);
    }
    ui.add_space(8.0);
    widgets::section_header(ui, "When it connects");
    ui.checkbox(&mut o.ask_before_start, "Ask before starting");
    ui.checkbox(
        &mut o.require_tor_only,
        "Pictures and input through Tor only",
    );
    // "Only while nobody is using this computer" and "Lock this computer
    // when a session ends" are not offered: nothing carries them out yet
    // (OPEN in docs/VERIFICATION.md, as the operator ruled).
    ui.add_space(8.0);
    widgets::section_header(ui, "For every device");
    let state = |on: bool| if on { "on" } else { "off" };
    // A Headless box grant turns this setting on when it is created.
    let awake = if headless && !manager.keep_awake {
        "on from Turn on (Headless box)"
    } else {
        state(manager.keep_awake)
    };
    line(
        ui,
        &format!("Keep this computer awake: {awake}"),
        t.text_secondary,
    );
    line(
        ui,
        &format!(
            "Prevent idle lock while unattended access is on: {}",
            state(manager.prevent_idle_lock)
        ),
        t.text_secondary,
    );
    line(ui, HOST_WIDE, t.text_secondary);
    if model.wizard.account == Some(AccountFacts::Linux) {
        ui.add_space(8.0);
        line(ui, LINUX_SENTENCE, t.text_secondary);
    }
    ui.add_space(10.0);
    ui.horizontal(|ui| {
        cancel(ui, true, close);
        if Button::new(Kind::Secondary, "Back")
            .small()
            .show(ui)
            .clicked()
        {
            // Back at ④ a new passphrase is drawn: none is shown twice.
            w.open_password();
        }
        let ready = !acknowledge || w.understood;
        if Button::new(Kind::Primary, "Continue")
            .small()
            .enabled(ready)
            .show(ui)
            .clicked()
            && ready
        {
            if level_step {
                // ⑤a first asks whether this computer can give the level.
                if let Some(probe) = w.with_level() {
                    actions.push(Action::Manager(ManagerOp::Preview(Box::new(probe))));
                    w.step = Step::Administrator;
                }
            } else if let Some(choice) = w.choice() {
                actions.push(Action::Manager(ManagerOp::Preview(Box::new(choice))));
                w.step = Step::Check;
            }
        }
    });
}

/// Whether the wizard offers ⑤a: the guard read this computer's account
/// facts, and they are not Linux's (an account whose facts could not be
/// read is offered the step and gets the guard's refusal there).
fn level_step(model: &Model) -> bool {
    matches!(
        model.wizard.account,
        Some(AccountFacts::Windows(_) | AccountFacts::Unreadable)
    )
}

/// The pinned label of the device the wizard gives access or changes.
fn label_of(model: &Model, w: &Wizard) -> String {
    if let Some(change) = &w.change {
        return change.label.clone();
    }
    model
        .wizard
        .devices
        .iter()
        .flatten()
        .find(|c| Some(c.device) == w.device)
        .map_or_else(String::new, |c| c.label.clone())
}

/// ⑤a (§B.8.7.1, decision M1-67): the administrator level, off in every
/// preset, its warning while on, and the grant's block window; where the
/// guard's preview of the choice with the level refused it, the guard's
/// reason and no switch. With the level on, ④ is the generator's only, with
/// the new-grant line under its passphrase: a password that was not shown
/// with that line goes, and Continue opens ④ again.
fn administrator(
    ui: &mut Ui,
    t: &Tokens,
    model: &Model,
    w: &mut Wizard,
    close: &mut bool,
    actions: &mut Vec<Action>,
) {
    let label = label_of(model, w);
    let probe = w.with_level();
    let refused = model
        .wizard
        .level_refused
        .as_ref()
        .filter(|(c, _)| Some(c) == probe.as_ref())
        .map(|(_, why)| *why);
    let judged = model
        .wizard
        .preview
        .as_ref()
        .is_some_and(|(c, _)| Some(c) == probe.as_ref());
    if let Some(why) = refused {
        w.options.admin = false;
        line(ui, why, t.text_primary);
    } else if judged {
        ui.checkbox(
            &mut w.options.admin,
            ADMINISTRATOR_PROMPT.replace("<device>", &label),
        );
        if w.options.admin {
            line(
                ui,
                &ADMINISTRATOR_WARNING.replace("<device>", &label),
                t.warn,
            );
        }
    } else {
        ui.spinner();
    }
    ui.add_space(6.0);
    line(
        ui,
        &format!("Time to stop a connection: {} s", w.options.block_window_s),
        t.text_secondary,
    );
    ui.add_space(10.0);
    ui.horizontal(|ui| {
        cancel(ui, true, close);
        if Button::new(Kind::Secondary, "Back")
            .small()
            .show(ui)
            .clicked()
        {
            w.step = Step::Options;
        }
        if Button::new(Kind::Primary, "Continue")
            .small()
            .show(ui)
            .clicked()
        {
            if w.options.admin && (w.own || !w.level_line) {
                // ④ again: a new passphrase, the generator's only, with the
                // new-grant line under it.
                w.note = None;
                w.open_password();
            } else if let Some(choice) = w.choice() {
                actions.push(Action::Manager(ManagerOp::Preview(Box::new(choice))));
                w.step = Step::Check;
            }
        }
    });
}

/// ⑥: this computer's readiness rows as the window host last read them,
/// with the static advisory (§B.8.7.1 ⑥); a red row needs "Enable anyway —
/// it will not work until fixed" before ⑦.
fn check(ui: &mut Ui, t: &Tokens, manager: &Manager, w: &mut Wizard, close: &mut bool) {
    let mut red = false;
    for (name, probe) in &manager.readiness {
        let (tone, text) = super::security::readiness_line(name, probe);
        red |= tone == Tone::Danger;
        ui.horizontal_top(|ui| {
            widgets::dot(ui, tone);
            line(ui, &text, t.text_primary);
        });
    }
    ui.add_space(6.0);
    line(ui, super::security::ADVISORY, t.text_muted);
    if red {
        ui.add_space(8.0);
        ui.checkbox(&mut w.enable_anyway, ENABLE_ANYWAY);
    } else {
        w.enable_anyway = false;
    }
    ui.add_space(10.0);
    ui.horizontal(|ui| {
        cancel(ui, true, close);
        if Button::new(Kind::Secondary, "Back")
            .small()
            .show(ui)
            .clicked()
        {
            w.step = Step::Options;
        }
        let ready = !red || w.enable_anyway;
        if Button::new(Kind::Primary, "Continue")
            .small()
            .enabled(ready)
            .show(ui)
            .clicked()
            && ready
        {
            w.step = Step::Summary;
        }
    });
}

/// What the meter says of an own password as typed (§B.8.7.2): whether it
/// may be used, and its lines (`true`: a plain line, `false`: a warning).
#[must_use]
pub(in super::super) fn meter(
    typed: &str,
    again: &str,
    policy: Option<&PolicyInputs>,
) -> (bool, Vec<(bool, String)>) {
    let Some(policy) = policy else {
        return (false, Vec::new());
    };
    if typed.is_empty() {
        return (false, Vec::new());
    }
    let inputs: Vec<&str> = policy.inputs.iter().map(String::as_str).collect();
    let checked = match password::check(typed, &inputs, policy.min_score >= 4) {
        Ok(c) => c,
        Err(PolicyError::TooShort { .. }) => {
            return (false, vec![(false, "At least 12 characters.".to_owned())]);
        }
        Err(PolicyError::TooLong { .. }) => {
            return (false, vec![(false, "At most 128 characters.".to_owned())]);
        }
        Err(PolicyError::TooWeak {
            score, required, ..
        }) => {
            return (
                false,
                vec![(
                    false,
                    format!(
                        "Too easy to guess: strength {score} of 4, and this computer needs \
                         {required}."
                    ),
                )],
            );
        }
        Err(_) => return (false, Vec::new()),
    };
    let mut lines = vec![(
        true,
        format!("Strength {} of 4: strong enough.", checked.score),
    )];
    let floor = if checked.score >= 4 {
        "at least about 2 months"
    } else {
        "at least about 14 hours"
    };
    lines.push((
        true,
        format!(
            "Offline guessing estimate: {floor} on one strong graphics card, if this computer's \
             Tornect data were stolen."
        ),
    ));
    if !checked.warnings.is_empty() {
        lines.push((
            false,
            "It starts or ends with a space: that space is part of the password.".to_owned(),
        ));
    }
    if again.is_empty() {
        return (false, lines);
    }
    if password::normalize(again) != checked.password {
        lines.push((false, DIFFER.to_owned()));
        return (false, lines);
    }
    (true, lines)
}

/// ⑦: what is given and *Turn on*, which sends the choice and the password
/// as press `attempt`; whether it was pressed.
#[allow(clippy::too_many_arguments)]
fn summary(
    ui: &mut Ui,
    t: &Tokens,
    model: &Model,
    manager: &Manager,
    w: &mut Wizard,
    close: &mut bool,
    attempt: u64,
    actions: &mut Vec<Action>,
) -> bool {
    // An own password waits for the guard's preview of this very choice; one
    // whose reach is or becomes non-zero (or cannot be judged) goes, and ④
    // offers the generator only.
    let judged = w.choice().and_then(|choice| {
        model
            .wizard
            .preview
            .as_ref()
            .filter(|(c, _)| *c == choice)
            .map(|(_, generated_only)| *generated_only)
    });
    if w.own && w.attempt.is_none() && judged.is_some_and(|j| j != Some(false)) {
        w.open_password();
        return false;
    }
    let label = model
        .wizard
        .devices
        .iter()
        .flatten()
        .find(|c| Some(c.device) == w.device)
        .map_or_else(String::new, |c| c.label.clone());
    let name = PRESETS
        .iter()
        .find(|(p, _)| *p == w.preset)
        .map_or("", |(_, n)| *n);
    line(ui, &format!("Device: {label}"), t.text_primary);
    line(ui, &format!("Used as: {name}"), t.text_primary);
    line(ui, &options_line(w.preset, &w.options), t.text_secondary);
    line(
        ui,
        if w.own {
            "Password: your own"
        } else {
            "Password: five generated words"
        },
        t.text_primary,
    );
    ui.add_space(8.0);
    if !manager.on {
        line(ui, ASKS_TWICE, t.text_secondary);
    }
    if manager.paused_until.is_some() {
        line(
            ui,
            &PAUSED_SUMMARY.replace("<device>", &label),
            t.text_secondary,
        );
    }
    let waiting = w.attempt.is_some();
    if waiting {
        ui.spinner();
    }
    ui.add_space(10.0);
    let mut pressed = false;
    ui.horizontal(|ui| {
        cancel(ui, !waiting, close);
        if Button::new(Kind::Secondary, "Back")
            .small()
            .enabled(!waiting)
            .show(ui)
            .clicked()
            && !waiting
        {
            w.open_password();
        }
        let own_judged = judged == Some(Some(false));
        let ready = !waiting && ((w.own && own_judged) || (!w.own && w.passphrase.is_some()));
        if pointer_only(ui, TURN_ON, ready) && ready {
            let new = if w.own {
                Some(NewPassword::Chosen(Secret(password::normalize(&w.typed))))
            } else {
                w.passphrase.take()
            };
            if let (Some(choice), Some(password)) = (w.choice(), new) {
                actions.push(Action::Manager(ManagerOp::Grant(Box::new(GrantRequest {
                    attempt,
                    choice,
                    password,
                }))));
                // Sent: the wizard keeps no copy.
                w.drop_passwords();
                w.attempt = Some(attempt);
                pressed = true;
            }
        }
    });
    pressed
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use egui::accesskit::{Node, Role};
    use tornect_core::unattended::readiness::Probe;

    use super::super::super::super::nav::Page;
    use super::super::super::super::view::{Form, main_window};
    use super::super::super::HIDDEN_WHILE_SHARED;
    use super::super::Section;
    use super::*;

    /// Tall enough for ①'s texts and its buttons.
    const WIDE: (f32, f32) = (1200.0, 1700.0);
    const NARROW: (f32, f32) = (560.0, 2600.0);

    /// Settings, Security in a main window driven one pass at a time, as the
    /// pages' own harness drives it; widgets are found in the accessibility
    /// tree, and what the window asked to copy is kept.
    struct Window {
        ctx: egui::Context,
        model: Model,
        form: Form,
        size: egui::Vec2,
        nodes: Vec<Node>,
        copied: Vec<String>,
    }

    impl Window {
        fn new(model: Model, size: (f32, f32)) -> Self {
            let ctx = egui::Context::default();
            ctx.enable_accesskit();
            ctx.set_theme(egui::Theme::Dark);
            let mut form = Form::default();
            form.page = Page::Settings;
            form.settings.section = Section::Security;
            let mut window = Self {
                ctx,
                model,
                form,
                size: egui::vec2(size.0, size.1),
                nodes: Vec::new(),
                copied: Vec::new(),
            };
            for _ in 0..3 {
                assert!(window.pass(Vec::new()).is_empty(), "nothing asked");
            }
            window
        }

        fn pass(&mut self, events: Vec<egui::Event>) -> Vec<Action> {
            let raw = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, self.size)),
                time: Some(5.0),
                events,
                ..egui::RawInput::default()
            };
            let mut actions = Vec::new();
            let now = Instant::now();
            let (model, form) = (&self.model, &mut self.form);
            let out = self.ctx.run_ui(raw, |ui| {
                main_window(ui, model, form, now, &mut actions);
            });
            if let Some(update) = &out.platform_output.accesskit_update {
                self.nodes = update.nodes.iter().map(|(_, n)| n.clone()).collect();
            }
            for command in &out.platform_output.commands {
                if let egui::OutputCommand::CopyText(text) = command {
                    self.copied.push(text.clone());
                }
            }
            out.drop_without_applying_deltas();
            actions
        }

        fn node(&self, label: &str) -> &Node {
            self.nodes
                .iter()
                .find(|n| n.label() == Some(label))
                .unwrap_or_else(|| panic!("no \"{label}\" on screen"))
        }

        fn center(&self, label: &str) -> egui::Pos2 {
            let b = self.node(label).bounds().expect("bounds");
            egui::pos2(((b.x0 + b.x1) / 2.0) as f32, ((b.y0 + b.y1) / 2.0) as f32)
        }

        fn press(&mut self, at: egui::Pos2, button: egui::PointerButton) -> Vec<Action> {
            let event = |pressed| egui::Event::PointerButton {
                pos: at,
                button,
                pressed,
                modifiers: egui::Modifiers::NONE,
            };
            let mut actions = self.pass(vec![egui::Event::PointerMoved(at), event(true)]);
            actions.extend(self.pass(vec![event(false)]));
            actions.extend(self.pass(Vec::new()));
            actions
        }

        /// A primary click on the control labelled `label`.
        fn click(&mut self, label: &str) -> Vec<Action> {
            let at = self.center(label);
            self.press(at, egui::PointerButton::Primary)
        }

        fn key_with(&mut self, key: egui::Key, modifiers: egui::Modifiers) -> Vec<Action> {
            let event = |pressed| egui::Event::Key {
                key,
                physical_key: None,
                pressed,
                repeat: false,
                modifiers,
            };
            let mut actions = self.pass(vec![event(true), event(false)]);
            actions.extend(self.pass(Vec::new()));
            actions
        }

        fn key(&mut self, key: egui::Key) -> Vec<Action> {
            self.key_with(key, egui::Modifiers::NONE)
        }

        fn has_text(&self, text: &str) -> bool {
            self.nodes
                .iter()
                .any(|n| n.value().is_some_and(|v| v.contains(text)))
        }

        fn has_control(&self, label: &str) -> bool {
            self.nodes.iter().any(|n| {
                n.label() == Some(label)
                    && matches!(
                        n.role(),
                        Role::Button | Role::TextInput | Role::CheckBox | Role::RadioButton
                    )
            })
        }

        fn wizard(&self) -> Option<&Wizard> {
            self.form.settings.wizard.as_ref()
        }

        fn step(&self) -> Option<Step> {
            self.wizard().map(|w| w.step)
        }

        /// The passphrase ④ shows now.
        fn phrase(&self) -> String {
            self.wizard()
                .and_then(|w| w.passphrase.as_ref())
                .map(|p| p.secret().0.as_str().to_owned())
                .expect("a passphrase")
        }

        /// Type `text` into the field labelled `label`.
        fn type_into(&mut self, label: &str, text: &str) {
            assert!(self.click(label).is_empty());
            self.pass(vec![egui::Event::Text(text.to_owned())]);
            self.pass(Vec::new());
        }
    }

    fn device(b: u8) -> DeviceId {
        DeviceId::from_bytes([b; 32])
    }

    /// A window host with unattended access off and one paired device
    /// without it, `attended` or not.
    fn model(attended: bool) -> Model {
        let mut model = Model {
            manager: Some(Manager {
                readiness: vec![("panic_key", Probe::Ok)],
                ..Manager::default()
            }),
            ..Model::default()
        };
        model.wizard.offer = Some(true);
        model.wizard.devices = Some(vec![Candidate {
            device: device(1),
            label: "Office laptop".to_owned(),
            words: None,
            attended,
        }]);
        model.wizard.policy = Some(PolicyInputs {
            inputs: vec!["tornect".to_owned()],
            min_score: 3,
        });
        model
    }

    /// "Turn on for a device…": the wizard at ①, and its one action.
    fn open(window: &mut Window) {
        assert_eq!(
            window.click(OPEN),
            vec![Action::Manager(ManagerOp::WizardDevices)]
        );
        assert_eq!(window.step(), Some(Step::Before));
    }

    /// ①'s Continue as it is a second after it stopped moving.
    fn arm(window: &mut Window) {
        // The step's layout settles over a few passes, and the button arms
        // again whenever it moves: wait until it keeps its place.
        let mut last = None;
        for _ in 0..10 {
            window.pass(Vec::new());
            let at = window.wizard().and_then(|w| w.armed).map(|(_, at)| at);
            if at.is_some() && at == last {
                break;
            }
            last = at;
        }
        let w = window.form.settings.wizard.as_mut().expect("open");
        if let Some((since, at)) = w.armed {
            w.armed = Some((
                since.checked_sub(Duration::from_secs(2)).expect("a past"),
                at,
            ));
        }
        // egui answers a press with the widgets of the pass before it: one
        // pass with the button armed.
        window.pass(Vec::new());
    }

    /// The choice ② and ③ make here, as the wizard builds it.
    fn choice() -> WizardChoice {
        let mut w = Wizard::new();
        w.device = Some(device(1));
        w.choice().expect("a device")
    }

    /// From "Turn on for a device…" to ④, the guard's preview of the choice
    /// answered `judged`.
    fn at_password(size: (f32, f32), judged: Option<bool>) -> Window {
        let mut window = Window::new(model(true), size);
        open(&mut window);
        arm(&mut window);
        assert!(window.click("Continue").is_empty());
        assert_eq!(window.step(), Some(Step::Device));
        assert!(window.click("Office laptop").is_empty());
        assert!(window.click("Continue").is_empty());
        assert_eq!(window.step(), Some(Step::Preset));
        assert_eq!(
            window.click("Continue"),
            vec![Action::Manager(ManagerOp::Preview(Box::new(choice())))]
        );
        assert_eq!(window.step(), Some(Step::Password));
        window.model.wizard.preview = Some((choice(), judged));
        window.pass(Vec::new());
        window
    }

    /// From ④ through ⑤ to ⑦, the guard's preview of the choice answered as
    /// before (the options unchanged).
    fn to_summary(window: &mut Window) {
        assert!(window.click("Continue").is_empty());
        assert_eq!(window.step(), Some(Step::Options));
        let judged = window.model.wizard.preview.as_ref().map(|(_, j)| *j);
        let sent = window.click("Continue");
        let Some(Action::Manager(ManagerOp::Preview(choice))) = sent.first() else {
            panic!("no preview asked: {sent:?}");
        };
        window.model.wizard.preview = Some(((**choice).clone(), judged.flatten()));
        window.pass(Vec::new());
        assert_eq!(window.step(), Some(Step::Check));
        assert!(window.click("Continue").is_empty());
        assert_eq!(window.step(), Some(Step::Summary));
    }

    /// The wizard at ⑤ for `preset`, with a file keystore or not.
    fn at_options(preset: &str, file_keystore: bool) -> Window {
        let mut model = model(true);
        if file_keystore {
            model.wizard.policy = Some(PolicyInputs {
                inputs: vec!["tornect".to_owned()],
                min_score: password::MIN_SCORE_FILE_KEYSTORE,
            });
        }
        let mut window = Window::new(model, WIDE);
        open(&mut window);
        arm(&mut window);
        assert!(window.click("Continue").is_empty());
        assert!(window.click("Office laptop").is_empty());
        assert!(window.click("Continue").is_empty());
        assert!(window.click(preset).is_empty());
        let sent = window.click("Continue");
        let Some(Action::Manager(ManagerOp::Preview(choice))) = sent.first() else {
            panic!("no preview asked: {sent:?}");
        };
        window.model.wizard.preview = Some(((**choice).clone(), Some(false)));
        window.pass(Vec::new());
        assert!(window.click("Continue").is_empty());
        assert_eq!(window.step(), Some(Step::Options));
        window
    }

    /// The options of the grant `window`'s Turn on sends, from ⑤.
    fn sent_options(window: &mut Window) -> GrantOptions {
        let sent = window.click("Continue");
        let Some(Action::Manager(ManagerOp::Preview(choice))) = sent.first() else {
            panic!("no preview asked: {sent:?}");
        };
        window.model.wizard.preview = Some(((**choice).clone(), Some(false)));
        window.pass(Vec::new());
        assert_eq!(window.step(), Some(Step::Check));
        assert!(window.click("Continue").is_empty());
        let sent = grants(&window.click(TURN_ON));
        assert_eq!(sent.len(), 1);
        assert_eq!(
            sent[0].choice, **choice,
            "the options judged are those sent"
        );
        sent[0].choice.options.clone()
    }

    fn options_mut(window: &mut Window) -> &mut Options {
        &mut window.form.settings.wizard.as_mut().expect("open").options
    }

    /// The window host with one device given access, `mode`, in its rows.
    fn with_a_grant(mode: SessionMode) -> Model {
        use super::super::super::super::model::GrantRow;
        use tornect_core::session_log::Actor;
        let mut model = model(true);
        if let Some(manager) = model.manager.as_mut() {
            manager.on = true;
            manager.grants = vec![GrantRow {
                device: device(1),
                label: "Office laptop".to_owned(),
                words: None,
                created_by: Some(Actor::Ui),
                last_used: None,
                state: "active".to_owned(),
                failures: 0,
            }];
        }
        model.wizard.modes = vec![(device(1), mode)];
        model
    }

    /// The change from the manager that registers the password only.
    fn no_change() -> WizardChoice {
        WizardChoice {
            device: device(1),
            preset: Preset::MyMachines,
            options: GrantOptions::default(),
        }
    }

    /// §B.8.7.3, decision M1-67: *Change password* is the wizard's ④ alone:
    /// its preview is of the change itself, "Use my own password" only where
    /// it says the reach stays 0 (never at the level), and its commit answers
    /// a primary pointer click only.
    #[test]
    fn change_password_at_the_level_offers_only_the_generator() {
        for (judged, offered) in [(Some(true), false), (None, false), (Some(false), true)] {
            let mut window = Window::new(with_a_grant(SessionMode::Control), WIDE);
            assert_eq!(
                window.click("Change password…"),
                vec![Action::Manager(ManagerOp::Preview(Box::new(no_change())))]
            );
            assert_eq!(window.step(), Some(Step::Password));
            assert!(window.has_text(CHANGE_PASSWORD));
            window.model.wizard.preview = Some((no_change(), judged));
            window.pass(Vec::new());
            assert_eq!(window.has_control(USE_MY_OWN), offered, "{judged:?}");
            assert!(!window.has_control("Back"), "④ alone");
            for key in [egui::Key::Enter, egui::Key::Space] {
                assert!(window.key(key).is_empty(), "{judged:?} {key:?}");
            }
            // No run of Tabs followed by Enter or Space sends the change.
            for tabs in 1..=4 {
                for key in [egui::Key::Enter, egui::Key::Space] {
                    let mut window = Window::new(with_a_grant(SessionMode::Control), WIDE);
                    window.click("Change password…");
                    window.model.wizard.preview = Some((no_change(), judged));
                    window.pass(Vec::new());
                    let mut actions = Vec::new();
                    for _ in 0..tabs {
                        actions.extend(window.key(egui::Key::Tab));
                    }
                    actions.extend(window.key(key));
                    let case = format!("{judged:?} {tabs} tabs {key:?}");
                    assert!(
                        !actions
                            .iter()
                            .any(|a| matches!(a, Action::Manager(ManagerOp::ChangePassword(_)))),
                        "{case}: sent"
                    );
                    assert!(
                        matches!(window.step(), None | Some(Step::Password)),
                        "{case}: went on"
                    );
                }
            }
        }
    }

    /// §B.8.7.3: *Change password* sends the change that changes nothing but
    /// the password (never the page's picture of the grant's options), with
    /// the generator's passphrase or the person's own as the one value; then
    /// keeps no copy and closes on the answer.
    #[test]
    fn change_password_sends_no_option_change() {
        for own in [false, true] {
            let mut window = Window::new(with_a_grant(SessionMode::Control), WIDE);
            window.click("Change password…");
            window.model.wizard.preview = Some((no_change(), Some(false)));
            window.pass(Vec::new());
            let expected = if own {
                assert!(window.click(USE_MY_OWN).is_empty());
                window.type_into(FIELD, OWN);
                window.type_into(AGAIN, OWN);
                NewPassword::Chosen(Secret(password::normalize(OWN)))
            } else {
                NewPassword::Generated(Secret(Zeroizing::new(window.phrase())))
            };
            let sent = window.click(CHANGE_PASSWORD);
            let [Action::Manager(ManagerOp::ChangePassword(request))] = sent.as_slice() else {
                panic!("{own}: {sent:?}");
            };
            assert_eq!(request.choice, no_change(), "{own}");
            assert_eq!(request.password, expected, "{own}");
            let w = window.wizard().expect("waiting");
            assert!(
                w.passphrase.is_none() && w.typed.is_empty(),
                "{own}: no copy"
            );
            window.model.wizard.answer = Some((request.attempt, WizardAnswer::Done));
            window.pass(Vec::new());
            assert!(window.wizard().is_none(), "{own}: closed on the answer");
        }
    }

    /// §B.8.7.3, PLAN's mode → Control (decision M1-67): *Change mode* of a
    /// view-only grant to control asks the guard's preview first; where
    /// control reaches the administrator level it is ④ with the plan's
    /// sentence and the generator only, and the one registration carries the
    /// mode; where it reaches nothing more, one operation that widens; a
    /// control grant goes to view only in one operation.
    #[test]
    fn mode_to_control_at_the_level_needs_a_new_password() {
        let to_control = WizardChoice {
            options: GrantOptions {
                mode: Some(SessionMode::Control),
                ..GrantOptions::default()
            },
            ..no_change()
        };
        for raises in [true, false] {
            let mut window = Window::new(with_a_grant(SessionMode::ViewOnly), WIDE);
            assert!(window.click("Change mode…").is_empty());
            assert_eq!(window.step(), Some(Step::Mode));
            assert!(window.has_text("Office laptop: View only"));
            assert_eq!(
                window.click("Continue"),
                vec![Action::Manager(ManagerOp::Preview(Box::new(
                    to_control.clone()
                )))]
            );
            window.model.wizard.raises = Some((to_control.clone(), Some(raises)));
            window.model.wizard.preview = Some((to_control.clone(), Some(raises)));
            window.pass(Vec::new());
            window.pass(Vec::new());
            if raises {
                assert_eq!(window.step(), Some(Step::Password));
                assert!(
                    window.has_text(&CONTROL_NEEDS_PASSWORD.replace("<device>", "Office laptop"))
                );
                assert!(!window.has_control(USE_MY_OWN), "the generator only");
                let shown = window.phrase();
                let sent = window.click(CHANGE_PASSWORD);
                let [Action::Manager(ManagerOp::ChangePassword(request))] = sent.as_slice() else {
                    panic!("{sent:?}");
                };
                assert_eq!(request.choice, to_control);
                assert_eq!(
                    request.password,
                    NewPassword::Generated(Secret(Zeroizing::new(shown)))
                );
            } else {
                assert_eq!(
                    window.click(TO_CONTROL),
                    vec![Action::Manager(ManagerOp::SetMode(
                        device(1),
                        SessionMode::Control
                    ))]
                );
                assert!(window.wizard().is_none());
            }
        }
        // A control grant: to view only, one operation.
        let mut window = Window::new(with_a_grant(SessionMode::Control), WIDE);
        assert!(window.click("Change mode…").is_empty());
        assert_eq!(
            window.click(TO_VIEW_ONLY),
            vec![Action::Manager(ManagerOp::SetMode(
                device(1),
                SessionMode::ViewOnly
            ))]
        );
        assert!(window.wizard().is_none());
    }

    /// §B.8.7.3: where *Change mode*'s preview could not judge whether
    /// control reaches programs that run as administrator, ④ says that
    /// Tornect cannot tell (a new generated password all the same); a judged
    /// raise keeps its sentence.
    #[test]
    fn an_unjudged_change_of_mode_says_it_cannot_tell() {
        let to_control = WizardChoice {
            options: GrantOptions {
                mode: Some(SessionMode::Control),
                ..GrantOptions::default()
            },
            ..no_change()
        };
        let cannot = CANNOT_TELL_NEEDS_PASSWORD.replace("<device>", "Office laptop");
        let reaches = CONTROL_NEEDS_PASSWORD.replace("<device>", "Office laptop");
        for judged in [None, Some(true)] {
            let mut window = Window::new(with_a_grant(SessionMode::ViewOnly), WIDE);
            assert!(window.click("Change mode…").is_empty());
            assert_eq!(
                window.click("Continue"),
                vec![Action::Manager(ManagerOp::Preview(Box::new(
                    to_control.clone()
                )))]
            );
            window.model.wizard.raises = Some((to_control.clone(), judged));
            window.model.wizard.preview = Some((to_control.clone(), judged));
            window.pass(Vec::new());
            window.pass(Vec::new());
            assert_eq!(window.step(), Some(Step::Password), "{judged:?}");
            assert_eq!(window.has_text(&cannot), judged.is_none(), "{judged:?}");
            assert_eq!(window.has_text(&reaches), judged.is_some(), "{judged:?}");
            assert_eq!(
                window.has_text("Control here can reach programs"),
                judged.is_some(),
                "{judged:?}"
            );
            assert!(!window.has_control(USE_MY_OWN), "{judged:?}");
        }
    }

    /// A new preview of an equal choice: the answer of an earlier one (of
    /// this opening or an earlier one) goes as the tokio side takes the new
    /// request, so neither ④'s "Use my own password" nor *Change mode*'s
    /// raise acts on it before the new answer lands.
    #[test]
    fn no_answer_of_an_earlier_preview_is_used() {
        // The wizard: back to ③ and on to ④ again.
        let mut window = at_password(WIDE, Some(false));
        assert!(window.has_control(USE_MY_OWN));
        assert!(window.click("Back").is_empty());
        assert_eq!(window.step(), Some(Step::Preset));
        assert_eq!(
            window.click("Continue"),
            vec![Action::Manager(ManagerOp::Preview(Box::new(choice())))]
        );
        // As the tokio side takes the request.
        window.model.wizard.forget_preview();
        window.pass(Vec::new());
        assert_eq!(window.step(), Some(Step::Password));
        assert!(!window.has_control(USE_MY_OWN), "the earlier answer");
        window.model.wizard.preview = Some((choice(), Some(false)));
        window.pass(Vec::new());
        assert!(window.has_control(USE_MY_OWN), "its own answer");

        // *Change password*, opened again over an answer of its last opening.
        let mut window = Window::new(with_a_grant(SessionMode::Control), WIDE);
        window.model.wizard.preview = Some((no_change(), Some(false)));
        assert_eq!(
            window.click("Change password…"),
            vec![Action::Manager(ManagerOp::Preview(Box::new(no_change())))]
        );
        window.model.wizard.forget_preview();
        window.pass(Vec::new());
        assert_eq!(window.step(), Some(Step::Password));
        assert!(
            !window.has_control(USE_MY_OWN),
            "an earlier opening's answer"
        );

        // *Change mode* to control, over a raise judged at an earlier opening.
        let to_control = WizardChoice {
            options: GrantOptions {
                mode: Some(SessionMode::Control),
                ..GrantOptions::default()
            },
            ..no_change()
        };
        let mut window = Window::new(with_a_grant(SessionMode::ViewOnly), WIDE);
        window.model.wizard.raises = Some((to_control.clone(), Some(false)));
        window.model.wizard.preview = Some((to_control.clone(), Some(false)));
        assert!(window.click("Change mode…").is_empty());
        assert_eq!(
            window.click("Continue"),
            vec![Action::Manager(ManagerOp::Preview(Box::new(
                to_control.clone()
            )))]
        );
        window.model.wizard.forget_preview();
        window.pass(Vec::new());
        window.pass(Vec::new());
        assert_eq!(window.step(), Some(Step::Mode));
        assert!(
            !window.has_control(TO_CONTROL),
            "an earlier opening's raise"
        );
        window.model.wizard.raises = Some((to_control, Some(false)));
        window.pass(Vec::new());
        assert!(window.has_control(TO_CONTROL), "its own answer");
    }

    /// §B.8.7.1 ⑥: this computer's readiness rows as the host read them; a
    /// red row needs "Enable anyway — it will not work until fixed" before ⑦
    /// (Continue does nothing until it is ticked), and with no red row
    /// nothing is asked.
    #[test]
    fn a_red_row_needs_enable_anyway() {
        for (rows, red) in [
            (
                vec![("panic_key", Probe::Ok), ("capture", Probe::Unknown)],
                false,
            ),
            (
                vec![
                    ("panic_key", Probe::Fail("not bound".to_owned())),
                    ("capture", Probe::Ok),
                ],
                true,
            ),
        ] {
            let mut window = at_options("My machines", false);
            window.model.manager.as_mut().expect("a guard").readiness = rows;
            let sent = window.click("Continue");
            let Some(Action::Manager(ManagerOp::Preview(chosen))) = sent.first() else {
                panic!("no preview asked: {sent:?}");
            };
            window.model.wizard.preview = Some(((**chosen).clone(), Some(false)));
            window.pass(Vec::new());
            assert_eq!(window.step(), Some(Step::Check), "{red}");
            assert!(window.has_text("Panic key"), "{red}");
            assert!(window.has_text(super::super::security::ADVISORY), "{red}");
            assert_eq!(window.has_control(ENABLE_ANYWAY), red);
            assert!(window.click("Continue").is_empty());
            if red {
                assert_eq!(window.step(), Some(Step::Check), "not without the tick");
                assert!(window.click(ENABLE_ANYWAY).is_empty());
                assert!(window.click("Continue").is_empty());
            }
            assert_eq!(window.step(), Some(Step::Summary), "{red}");
        }
    }

    /// §B.8.7.2: a password field takes one character more than the policy
    /// allows and no more, inside the room reserved before typing, so a long
    /// paste never makes it grow; the meter says how long a password may be.
    #[test]
    fn a_long_paste_never_grows_a_password_field() {
        let mut window = at_password(WIDE, Some(false));
        assert!(window.click(USE_MY_OWN).is_empty());
        assert!(window.click(FIELD).is_empty());
        window.pass(vec![egui::Event::Paste("x7!Qz".repeat(120))]);
        window.pass(Vec::new());
        let w = window.wizard().expect("open");
        assert_eq!(w.typed.chars().count(), FIELD_CHARS);
        assert_eq!(w.typed.capacity(), FIELD_ROOM);
        assert!(window.has_text("At most 128 characters."));
        // The second field keeps the same limit and room.
        assert!(window.click(AGAIN).is_empty());
        window.pass(vec![egui::Event::Paste("x7!Qz".repeat(120))]);
        window.pass(Vec::new());
        let w = window.wizard().expect("open");
        assert_eq!(w.again.chars().count(), FIELD_CHARS);
        assert_eq!(w.again.capacity(), FIELD_ROOM);
    }

    /// §B.8.6.1: a device without a completed attended session gets access
    /// only with the waiver: ②'s Continue does nothing until the waiver is
    /// ticked, and the choice carries the waiver only then (a device whose
    /// attended session completed is asked none and sends none).
    #[test]
    fn the_waiver_is_needed_for_a_device_without_an_attended_session() {
        assert!(!choice().options.waive_attended_precondition);
        let mut window = Window::new(model(false), WIDE);
        open(&mut window);
        arm(&mut window);
        assert!(window.click("Continue").is_empty());
        assert_eq!(window.step(), Some(Step::Device));
        assert!(!window.has_control(WAIVER), "not before a device is chosen");
        assert!(window.click("Office laptop").is_empty());
        assert!(window.has_control(WAIVER));
        assert!(window.click("Continue").is_empty());
        assert_eq!(window.step(), Some(Step::Device), "inert until the tick");
        assert!(window.click(WAIVER).is_empty());
        assert!(window.click("Continue").is_empty());
        assert_eq!(window.step(), Some(Step::Preset));
        let sent = window.click("Continue");
        let Some(Action::Manager(ManagerOp::Preview(chosen))) = sent.first() else {
            panic!("no preview asked: {sent:?}");
        };
        assert!(chosen.options.waive_attended_precondition);
    }

    /// §B.8.6.1: ③ draws each preset's defaults under its name, in `PRESETS`
    /// order and in exactly these words, at both widths (built behaviour,
    /// pinned).
    #[test]
    fn the_preset_step_shows_each_presets_defaults() {
        let lines = [
            "Control · 3 s to stop a connection · ends after 90 days without use",
            "View only · 10 s to stop a connection · asks you before starting · starts working \
             12 hours after it is given · ends after 7 days · sessions of up to 4 hours",
            "Control · no time to stop a connection · ends after 90 days without use · keeps this \
             computer awake",
        ];
        for ((preset, name), want) in PRESETS.into_iter().zip(lines) {
            assert_eq!(preset_defaults(preset), want, "{name}");
        }
        for size in [WIDE, NARROW] {
            let mut window = Window::new(model(true), size);
            open(&mut window);
            arm(&mut window);
            assert!(window.click("Continue").is_empty());
            assert!(window.click("Office laptop").is_empty());
            assert!(window.click("Continue").is_empty());
            assert_eq!(window.step(), Some(Step::Preset));
            let mut below = 0.0;
            for ((_, name), want) in PRESETS.into_iter().zip(lines) {
                assert!(window.has_control(name), "{size:?}: {name}");
                let radio = window.node(name).bounds().expect("bounds");
                let line = window
                    .nodes
                    .iter()
                    .find(|n| n.value() == Some(want))
                    .and_then(|n| n.bounds())
                    .unwrap_or_else(|| panic!("{size:?}: no line {want:?}"));
                assert!(radio.y0 >= below, "{size:?}: {name} after the line above");
                assert!(line.y0 >= radio.y1 - 1.0, "{size:?}: {want:?} under {name}");
                below = line.y1 - 1.0;
            }
        }
    }

    /// §B.8.7.1 ⑦: the summary also names the preset's defaults that ⑤ does
    /// not change, in ③'s words, and a hard lock of 0 as none after failed
    /// attempts in a row; ⑤ for Headless box, while keep-awake is off here,
    /// says that Turn on turns it on.
    #[test]
    fn the_summary_names_the_defaults_the_options_keep() {
        let helping = options_line(Preset::HelpingSomeone, &Options::of(Preset::HelpingSomeone));
        assert_eq!(
            helping,
            "View only · 10 s to stop a connection · asks you before starting · starts working 12 \
             hours after it is given · ends after 7 days · sessions of up to 4 hours · hard lock \
             after 10 failed attempts in a row"
        );
        let mut headless = Options::of(Preset::HeadlessBox);
        headless.hard_lock_after = 0;
        assert_eq!(
            options_line(Preset::HeadlessBox, &headless),
            "Control · no time to stop a connection · ends after 90 days without use · keeps this \
             computer awake · no hard lock after failed attempts in a row"
        );
        let window = at_options("Headless box", false);
        assert!(window.has_text("Keep this computer awake: on from Turn on (Headless box)"));
        let mut window = at_options("Helping someone", false);
        let sent = window.click("Continue");
        let Some(Action::Manager(ManagerOp::Preview(choice))) = sent.first() else {
            panic!("no preview asked: {sent:?}");
        };
        window.model.wizard.preview = Some(((**choice).clone(), Some(false)));
        window.pass(Vec::new());
        assert_eq!(window.step(), Some(Step::Check));
        assert!(window.click("Continue").is_empty());
        assert_eq!(window.step(), Some(Step::Summary));
        assert!(window.has_text(&helping));
    }

    /// §B.8.7.2: the wizard and its passwords go when the window leaves
    /// Settings, Security, for another section or another page: the own
    /// password's fields and their state with it.
    #[test]
    fn leaving_the_section_or_the_page_closes_the_wizard() {
        for leave in ["General", "Home"] {
            let mut window = at_password(WIDE, Some(false));
            assert!(window.click(USE_MY_OWN).is_empty());
            window.type_into(FIELD, OWN);
            let state = |window: &Window, id: &str| {
                egui::text_edit::TextEditState::load(&window.ctx, egui::Id::new(id))
            };
            assert!(state(&window, FIELD_IDS[0]).is_some(), "{leave}");
            assert!(window.click(leave).is_empty(), "{leave}");
            window.pass(Vec::new());
            assert!(window.wizard().is_none(), "{leave}");
            for id in FIELD_IDS {
                assert!(state(&window, id).is_none(), "{leave}: {id}");
            }
        }
    }

    /// §B.8.7.1 ⑤, §B.8.6.1: each option keeps its rule, and every option
    /// goes into the one registration. "Never" only with its warning, and
    /// not offered on a file keystore or where the preset caps the expiry;
    /// the time to stop a connection within the preset's bounds (Helping
    /// someone at least 5 s); a hard lock of 0 with the plan's warning;
    /// lock-on-disconnect and "only while nobody is using this computer" not
    /// offered (nothing carries them out yet) and saved as off; keep-awake and
    /// the idle lock shown as they are, set on the Security page only.
    #[test]
    fn each_option_keeps_its_planned_rule() {
        // My machines on an OS keychain: never, with its warning; the hard lock
        // off, warned; the two options not offered; the others as ticked.
        let mut window = at_options("My machines", false);
        assert!(!window.has_text(NEVER_WARNING));
        assert!(window.click("Never").is_empty());
        assert!(window.has_text(NEVER_WARNING));
        options_mut(&mut window).hard_lock_after = 0;
        window.pass(Vec::new());
        assert!(window.has_text(HARD_LOCK_OFF));
        // No value the hard lock's slider offers turns the lock in a row off
        // without that warning: it ends below the lifetime budget.
        let hard_lock = window
            .nodes
            .iter()
            .find(|n| n.role() == Role::Slider && n.numeric_value() == Some(0.0))
            .expect("the hard lock's slider");
        assert_eq!(hard_lock.min_numeric_value(), Some(0.0));
        assert_eq!(
            hard_lock.max_numeric_value(),
            Some(f64::from(
                tornect_core::unattended::grant::LIFETIME_BUDGET - 1
            ))
        );
        assert!(!window.has_control("Lock this computer when a session ends"));
        assert!(!window.has_control("Only while nobody is using this computer"));
        assert!(window.click("View only").is_empty());
        for line in [
            "Keep this computer awake: off",
            "Prevent idle lock while unattended access is on: off",
            HOST_WIDE,
        ] {
            assert!(window.has_text(line), "{line}");
        }
        for label in [
            "Keep this computer awake",
            "Prevent idle lock while unattended access is on",
        ] {
            assert!(
                !window.has_control(label),
                "{label}: set on the Security page"
            );
        }
        let sent = sent_options(&mut window);
        assert_eq!(sent.expires_at, Some(0));
        assert_eq!(sent.hard_lock_after, Some(0));
        assert_eq!(sent.lock_on_disconnect, Some(false));
        assert_eq!(sent.require_absent, Some(false));
        assert_eq!(sent.require_tor_only, Some(false));
        assert_eq!(sent.mode, Some(SessionMode::ViewOnly));
        assert_eq!(sent.block_window_s, Some(3));
        assert_eq!(sent.ask_before_start, Some(false));
        // A file keystore: never is not offered.
        let window = at_options("My machines", true);
        assert!(!window.has_control("Never"));
        // Headless box caps the expiry and refuses lock-on-disconnect.
        let window = at_options("Headless box", false);
        assert!(!window.has_control("Never"));
        assert!(!window.has_control("Lock this computer when a session ends"));
        // Helping someone: at least 5 s to stop a connection, asks first.
        let mut window = at_options("Helping someone", false);
        let slider = window
            .nodes
            .iter()
            .find(|n| n.role() == Role::Slider)
            .expect("the slider");
        assert_eq!(slider.min_numeric_value(), Some(5.0));
        assert_eq!(
            slider.max_numeric_value(),
            Some(f64::from(MAX_BLOCK_WINDOW_S))
        );
        options_mut(&mut window).block_window_s = 0;
        window.pass(Vec::new());
        assert_eq!(options_mut(&mut window).block_window_s, 5, "kept in bounds");
        let sent = sent_options(&mut window);
        assert_eq!(sent.block_window_s, Some(5));
        assert_eq!(sent.ask_before_start, Some(true));
        assert_eq!(sent.mode, Some(SessionMode::ViewOnly));
    }

    /// §B.8.7.1 ④, ⑤ (decision M1-67): an option that makes the reach
    /// non-zero after an own password was chosen (control where control
    /// reaches the administrator level) takes it away: back at ④, the own
    /// password wiped, the generator only.
    #[test]
    fn a_chosen_password_goes_when_an_option_makes_the_reach_non_zero() {
        let mut window = at_options("Helping someone", false);
        assert!(window.click("Back").is_empty());
        assert_eq!(window.step(), Some(Step::Password));
        assert!(window.click(USE_MY_OWN).is_empty());
        window.type_into(FIELD, OWN);
        window.type_into(AGAIN, OWN);
        assert!(window.click("Continue").is_empty());
        assert_eq!(window.step(), Some(Step::Options));
        assert!(window.click("Control").is_empty());
        let sent = window.click("Continue");
        let Some(Action::Manager(ManagerOp::Preview(choice))) = sent.first() else {
            panic!("no preview asked: {sent:?}");
        };
        assert_eq!(choice.options.mode, Some(SessionMode::Control));
        assert_eq!(window.step(), Some(Step::Check));
        assert!(window.click("Continue").is_empty());
        // Turn on waits for the preview of this choice.
        assert!(window.wizard().unwrap().own);
        assert!(grants(&window.click(TURN_ON)).is_empty(), "not judged yet");
        window.model.wizard.preview = Some(((**choice).clone(), Some(true)));
        window.pass(Vec::new());
        window.pass(Vec::new());
        assert_eq!(window.step(), Some(Step::Password));
        let w = window.wizard().unwrap();
        assert!(!w.own && w.typed.is_empty() && w.again.is_empty());
        assert!(!window.has_control(USE_MY_OWN));
        window.phrase();
    }

    /// ④ to ⑦ with the generator's passphrase.
    fn at_summary(size: (f32, f32)) -> Window {
        let mut window = at_password(size, Some(false));
        to_summary(&mut window);
        window
    }

    /// The wizard's grants among `actions`.
    fn grants(actions: &[Action]) -> Vec<GrantRequest> {
        actions
            .iter()
            .filter_map(|a| match a {
                Action::Manager(ManagerOp::Grant(request)) => Some((**request).clone()),
                _ => None,
            })
            .collect()
    }

    const OWN: &str = "quiet verdant otter lantern 41";

    /// §B.8.7.1 ①: the explanation, the scam line, this system's limits and
    /// the six disclosures as approved; Continue is armed after a second and
    /// answers a primary pointer click only: not before, not to Enter or
    /// Space, not to a secondary click.
    #[test]
    fn the_scam_step_continues_by_pointer_only() {
        let limits = if cfg!(windows) {
            LIMITS_WINDOWS
        } else {
            LIMITS_LINUX
        };
        for size in [WIDE, NARROW] {
            let mut window = Window::new(model(true), size);
            open(&mut window);
            for text in [EXPLANATION, SCAM, limits[0], limits[1]]
                .into_iter()
                .chain(DISCLOSURES)
            {
                assert!(window.has_text(text), "{size:?}: {text}");
            }
            assert!(window.click("Continue").is_empty());
            assert_eq!(window.step(), Some(Step::Before), "{size:?}: not armed");
            arm(&mut window);
            for key in [egui::Key::Enter, egui::Key::Space] {
                assert!(window.key(key).is_empty());
                assert_eq!(window.step(), Some(Step::Before), "{size:?}: {key:?}");
            }
            let at = window.center("Continue");
            assert!(window.press(at, egui::PointerButton::Secondary).is_empty());
            assert_eq!(window.step(), Some(Step::Before), "{size:?}: secondary");
            assert!(
                window.click("Continue").is_empty(),
                "{size:?}: nothing sent"
            );
            assert_eq!(window.step(), Some(Step::Device), "{size:?}");
            assert!(window.has_text(Step::Device.title()), "{size:?}");
        }
    }

    /// M-UI-3's "no keyboard path to an accept" on the wizard's trust steps
    /// (①, ④, ⑦): no run of Tabs followed by Enter or Space goes forward or
    /// sends the grant; the keyboard can only cancel or go back.
    #[test]
    fn the_wizard_trust_steps_keys_only_refuse() {
        type Make = fn() -> Window;
        let steps: [(Step, Make); 3] = [
            (Step::Before, || {
                let mut window = Window::new(model(true), WIDE);
                open(&mut window);
                arm(&mut window);
                window
            }),
            (Step::Password, || at_password(WIDE, Some(false))),
            (Step::Summary, || at_summary(WIDE)),
        ];
        for (step, make) in steps {
            for tabs in 0..=10 {
                for key in [egui::Key::Enter, egui::Key::Space] {
                    let mut window = make();
                    let mut actions = Vec::new();
                    for _ in 0..tabs {
                        actions.extend(window.key(egui::Key::Tab));
                    }
                    actions.extend(window.key(key));
                    let case = format!("{step:?} {tabs} tabs {key:?}");
                    assert!(grants(&actions).is_empty(), "{case}: sent");
                    let order = |s: Option<Step>| match s {
                        None => 0,
                        Some(Step::Before) => 1,
                        Some(Step::Device) => 2,
                        Some(Step::Preset) => 3,
                        Some(Step::Password) => 4,
                        Some(Step::Options | Step::Administrator) => 5,
                        Some(Step::Check) => 6,
                        Some(Step::Summary | Step::Offer) => 7,
                        Some(Step::Mode | Step::Raise | Step::Restore) => 8,
                    };
                    assert!(order(window.step()) <= order(Some(step)), "{case}: went on");
                }
            }
        }
    }

    /// ④ and ⑦ complete by a primary pointer click only: Enter in a filled
    /// own password's field, Enter or Space at ⑦ send nothing and go
    /// nowhere; the click on Continue and on Turn on do.
    #[test]
    fn no_key_completes_the_password_step_or_turn_on() {
        let mut window = at_password(WIDE, Some(false));
        assert!(window.click(USE_MY_OWN).is_empty());
        window.type_into(FIELD, OWN);
        window.type_into(AGAIN, OWN);
        // Enter in the field that has the focus (a Space there would type).
        assert!(window.key(egui::Key::Enter).is_empty());
        assert_eq!(window.step(), Some(Step::Password));
        to_summary(&mut window);
        for key in [egui::Key::Enter, egui::Key::Space, egui::Key::Tab] {
            assert!(window.key(key).is_empty(), "{key:?}");
            assert_eq!(window.step(), Some(Step::Summary), "{key:?}");
        }
        let sent = grants(&window.click(TURN_ON));
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].choice, choice());
    }

    /// Decision M1-67, §B.8.7.1 ④: "Use my own password" only once the
    /// guard's preview of this very choice said the reach stays 0; never
    /// while it says the reach is or becomes non-zero, nor before it
    /// answered, nor for another choice, nor once *Turn on* found a raise;
    /// and an own password already typed goes when the reach becomes
    /// non-zero.
    #[test]
    fn no_use_my_own_while_the_reach_is_or_becomes_non_zero() {
        for size in [WIDE, NARROW] {
            for (judged, offered) in [(Some(true), false), (None, false), (Some(false), true)] {
                let window = at_password(size, judged);
                assert_eq!(
                    window.has_control(USE_MY_OWN),
                    offered,
                    "{size:?} {judged:?}"
                );
            }
            // Not before the preview answered, nor for another choice.
            let mut window = at_password(size, Some(false));
            window.model.wizard.preview = None;
            window.pass(Vec::new());
            assert!(!window.has_control(USE_MY_OWN), "{size:?}: not judged");
            let mut other = choice();
            other.device = device(2);
            window.model.wizard.preview = Some((other, Some(false)));
            window.pass(Vec::new());
            assert!(!window.has_control(USE_MY_OWN), "{size:?}: another choice");
            // An own password typed, then the reach becomes non-zero.
            window.model.wizard.preview = Some((choice(), Some(false)));
            window.pass(Vec::new());
            assert!(window.click(USE_MY_OWN).is_empty());
            window.type_into(FIELD, OWN);
            window.model.wizard.preview = Some((choice(), Some(true)));
            window.pass(Vec::new());
            let w = window.wizard().expect("open");
            assert!(!w.own && w.typed.is_empty(), "{size:?}: the own one goes");
            assert!(!window.has_control(FIELD) && !window.has_control(USE_MY_OWN));
            // Turn on found a raise: the generator only, from then on.
            let mut window = at_summary(size);
            let sent = grants(&window.click(TURN_ON));
            window.model.wizard.answer = Some((sent[0].attempt, WizardAnswer::NeedsGenerated));
            window.pass(Vec::new());
            window.pass(Vec::new());
            assert_eq!(window.step(), Some(Step::Password), "{size:?}");
            assert!(window.has_text(NEEDS_GENERATED), "{size:?}");
            assert!(!window.has_control(USE_MY_OWN), "{size:?}: after a raise");
            assert_ne!(window.phrase(), "", "{size:?}: a new passphrase");
        }
    }

    /// Decision M1-67: the grant is sent with the generator's arm only when
    /// the generator's passphrase is what goes: shown, then "Use my own
    /// password", typed: chosen; typed, then "Use a generated password":
    /// generated, the passphrase shown.
    #[test]
    fn only_the_generator_sends_generated() {
        // The generator first, then an own password.
        let mut window = at_password(WIDE, Some(false));
        window.phrase();
        assert!(window.click(USE_MY_OWN).is_empty());
        assert!(
            window.wizard().unwrap().passphrase.is_none(),
            "the passphrase goes"
        );
        window.type_into(FIELD, OWN);
        window.type_into(AGAIN, OWN);
        to_summary(&mut window);
        let sent = grants(&window.click(TURN_ON));
        assert_eq!(
            sent[0].password,
            NewPassword::Chosen(Secret(password::normalize(OWN)))
        );
        // An own password first, then the generator.
        let mut window = at_password(WIDE, Some(false));
        assert!(window.click(USE_MY_OWN).is_empty());
        window.type_into(FIELD, OWN);
        assert!(window.click(USE_GENERATED).is_empty());
        let w = window.wizard().unwrap();
        assert!(!w.own && w.typed.is_empty(), "the own one goes");
        let shown = window.phrase();
        assert!(window.has_text(&shown));
        to_summary(&mut window);
        let sent = grants(&window.click(TURN_ON));
        assert_eq!(
            sent[0].password,
            NewPassword::Generated(Secret(Zeroizing::new(shown)))
        );
    }

    /// §B.8.7.1 ④: the passphrase is shown once, on ④ only, as text that
    /// cannot be selected: a drag over it and Copy copy nothing; ⑦ does not
    /// show it, and back at ④ a new one is drawn; once sent, the wizard
    /// keeps none.
    #[test]
    fn the_passphrase_is_shown_once_and_never_copied() {
        for size in [WIDE, NARROW] {
            let mut window = at_password(size, Some(false));
            let first = window.phrase();
            // Five words; a list word with a hyphen reads as two (§B.8.7.2).
            assert!(first.split(' ').count() >= 5, "{size:?}: five words");
            assert!(window.has_text(&first), "{size:?}");
            assert!(window.has_text(WRITE_IT_DOWN), "{size:?}");
            let b = window
                .nodes
                .iter()
                .find(|n| n.value() == Some(first.as_str()))
                .and_then(Node::bounds)
                .expect("the passphrase's place");
            let (from, to) = (
                egui::pos2(b.x0 as f32 + 1.0, ((b.y0 + b.y1) / 2.0) as f32),
                egui::pos2(b.x1 as f32 - 1.0, ((b.y0 + b.y1) / 2.0) as f32),
            );
            let button = |pos, pressed| egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: egui::Modifiers::NONE,
            };
            window.pass(vec![egui::Event::PointerMoved(from), button(from, true)]);
            window.pass(vec![egui::Event::PointerMoved(to)]);
            window.pass(vec![button(to, false)]);
            window.pass(vec![egui::Event::Copy]);
            window.key_with(egui::Key::C, egui::Modifiers::COMMAND);
            assert!(window.copied.is_empty(), "{size:?}: {:?}", window.copied);
            to_summary(&mut window);
            assert!(!window.has_text(&first), "{size:?}: not at ⑦");
            assert!(window.click("Back").is_empty());
            assert_eq!(window.step(), Some(Step::Password), "{size:?}");
            let second = window.phrase();
            assert_ne!(second, first, "{size:?}: a new one");
            assert!(!window.has_text(&first), "{size:?}: never again");
            to_summary(&mut window);
            assert_eq!(grants(&window.click(TURN_ON)).len(), 1);
            let w = window.wizard().expect("waiting");
            assert!(
                w.passphrase.is_none() && w.typed.is_empty(),
                "{size:?}: none kept"
            );
        }
    }

    /// §B.8.7.2: ④'s own password fields keep no undo copy of what is typed
    /// (cleared every frame), and Back and Cancel wipe them with their state.
    #[test]
    fn a_password_field_is_cleared_with_its_undo_state() {
        let undo_empty = |window: &Window, id: &str| {
            egui::text_edit::TextEditState::load(&window.ctx, egui::Id::new(id)).is_none_or(
                |state| {
                    let undoer = state.undoer();
                    !undoer.is_in_flux() && format!("{undoer:?}").contains("undo count: 0")
                },
            )
        };
        for leave in ["Back", "Cancel"] {
            let mut window = at_password(WIDE, Some(false));
            assert!(window.click(USE_MY_OWN).is_empty());
            window.type_into(FIELD, OWN);
            window.type_into(AGAIN, "another typed text 77");
            assert_eq!(window.wizard().unwrap().typed.as_str(), OWN);
            for id in FIELD_IDS {
                assert!(undo_empty(&window, id), "{leave}: {id}");
            }
            assert!(window.click(leave).is_empty());
            window.pass(Vec::new());
            if let Some(w) = window.wizard() {
                assert!(
                    w.typed.is_empty() && w.again.is_empty() && !w.own,
                    "{leave}"
                );
            }
            for id in FIELD_IDS {
                assert!(
                    egui::text_edit::TextEditState::load(&window.ctx, egui::Id::new(id)).is_none(),
                    "{leave}: {id}'s state goes"
                );
            }
        }
    }

    /// §B.8.7.2: nothing typed into ④'s fields can be copied or cut out.
    #[test]
    fn no_copy_leaves_a_password_field() {
        let mut window = at_password(WIDE, Some(false));
        assert!(window.click(USE_MY_OWN).is_empty());
        for field in [FIELD, AGAIN] {
            window.type_into(field, OWN);
            window.key_with(egui::Key::A, egui::Modifiers::COMMAND);
            window.pass(vec![egui::Event::Copy]);
            window.pass(vec![egui::Event::Cut]);
            window.key_with(egui::Key::C, egui::Modifiers::COMMAND);
            let menu = window.center(field);
            window.press(menu, egui::PointerButton::Secondary);
        }
        assert!(window.copied.is_empty(), "{:?}", window.copied);
    }

    /// While this screen may be in a picture that leaves it, the wizard
    /// closes, its passwords go, the hidden card shows, and it is not
    /// offered; after, it starts again from "Turn on for a device…".
    #[test]
    fn the_wizard_while_shared_shows_the_hidden_card() {
        for size in [WIDE, NARROW] {
            let mut window = at_password(size, Some(false));
            let phrase = window.phrase();
            window.model.hosted_elsewhere = true;
            window.pass(Vec::new());
            window.pass(Vec::new());
            assert!(window.wizard().is_none(), "{size:?}");
            assert!(window.has_text(HIDDEN_WHILE_SHARED), "{size:?}");
            assert!(!window.has_text(&phrase), "{size:?}");
            assert!(!window.has_control(OPEN), "{size:?}");
            window.model.hosted_elsewhere = false;
            window.pass(Vec::new());
            assert!(window.has_control(OPEN), "{size:?}");
            assert!(window.wizard().is_none(), "{size:?}");
        }
    }

    // ------------------------------------------------------------ ⑤a (§B.8.7.1)

    /// An installed Tornect on a Windows administrator account, as the guard
    /// reads its facts.
    fn windows_admin() -> AccountFacts {
        AccountFacts::Windows(tornect_core::levels::WindowsFacts {
            installed: true,
            administrator: true,
            ..Default::default()
        })
    }

    /// The wizard at ⑤ for `preset` with the guard's account facts
    /// `account`, then ⑤'s Continue (for *Helping someone*, View only by
    /// default, after choosing Control, since ⑤a is a step of control; for
    /// *Headless box* with no time to stop a connection, after its "I
    /// understand"): the preview it asked for.
    fn continue_from_options(
        preset: &str,
        account: Option<AccountFacts>,
    ) -> (Window, WizardChoice) {
        let mut window = at_options(preset, false);
        window.model.wizard.account = account;
        window.pass(Vec::new());
        if preset == "Helping someone" {
            assert!(window.click("Control").is_empty());
        }
        if window.has_control(I_UNDERSTAND) {
            assert!(window.click(I_UNDERSTAND).is_empty());
        }
        let sent = window.click("Continue");
        let Some(Action::Manager(ManagerOp::Preview(choice))) = sent.first() else {
            panic!("no preview asked: {sent:?}");
        };
        let choice = (**choice).clone();
        (window, choice)
    }

    /// The guard's preview of `choice` answered: whether its password can
    /// only be generated, or the level refused for `why`.
    fn judge(
        window: &mut Window,
        choice: &WizardChoice,
        generated_only: Option<bool>,
        why: Option<&'static str>,
    ) {
        window.model.wizard.preview = Some((choice.clone(), generated_only));
        window.model.wizard.level_refused = why.map(|why| (choice.clone(), why));
        window.pass(Vec::new());
    }

    /// ⑤a's switch for the fixture's device.
    fn prompt() -> String {
        ADMINISTRATOR_PROMPT.replace("<device>", "Office laptop")
    }

    /// §B.8.7.1 ⑤a: the step follows ⑤ only where the guard read account
    /// facts that are not Linux's (none read: no step); it asks the guard's
    /// preview of the choice with the level, and its switch is off in every
    /// preset, so the grant it sends on carries no level.
    #[test]
    fn the_administrator_step_is_windows_only_and_off_in_every_preset() {
        for preset in [
            Preset::MyMachines,
            Preset::HelpingSomeone,
            Preset::HeadlessBox,
        ] {
            assert!(!Options::of(preset).admin, "{preset:?}");
        }
        for account in [None, Some(AccountFacts::Linux)] {
            let (window, choice) = continue_from_options("My machines", account);
            assert_eq!(window.step(), Some(Step::Check), "{account:?}");
            assert_eq!(choice.options.elevation, None, "{account:?}");
            assert!(!window.has_control(&prompt()), "{account:?}");
        }
        for preset in ["My machines", "Headless box"] {
            let (mut window, probe) = continue_from_options(preset, Some(windows_admin()));
            assert_eq!(window.step(), Some(Step::Administrator), "{preset}");
            assert_eq!(
                probe.options.elevation,
                Some(Elevation::Admin),
                "{preset}: the preview of the level"
            );
            judge(&mut window, &probe, Some(true), None);
            assert!(window.has_control(&prompt()), "{preset}");
            assert!(!window.wizard().expect("open").options.admin, "{preset}");
            assert!(
                !window.has_text(&ADMINISTRATOR_WARNING.replace("<device>", "Office laptop")),
                "{preset}: no warning while off"
            );
            let sent = window.click("Continue");
            let Some(Action::Manager(ManagerOp::Preview(choice))) = sent.first() else {
                panic!("{preset}: no preview asked: {sent:?}");
            };
            assert_eq!(choice.options.elevation, None, "{preset}: no level");
            assert_eq!(window.step(), Some(Step::Check), "{preset}");
        }
    }

    /// §B.8.7.1 ⑤a: the administrator level is a level of control: with View
    /// only at ⑤ the wizard goes on with no ⑤a, and its choice carries no
    /// level, also after ⑤a had turned it on for control.
    #[test]
    fn view_only_offers_no_administrator_step() {
        let mut window = at_options("My machines", false);
        window.model.wizard.account = Some(windows_admin());
        window.pass(Vec::new());
        assert!(window.click("View only").is_empty());
        let sent = window.click("Continue");
        let Some(Action::Manager(ManagerOp::Preview(choice))) = sent.first() else {
            panic!("no preview asked: {sent:?}");
        };
        assert_eq!(window.step(), Some(Step::Check), "no ⑤a");
        assert_eq!(choice.options.mode, Some(SessionMode::ViewOnly));
        assert_eq!(choice.options.elevation, None);
        // The level on at ⑤a for control, then back to ⑤ and View only.
        let (mut window, probe) = continue_from_options("My machines", Some(windows_admin()));
        judge(&mut window, &probe, Some(true), None);
        assert!(window.click(&prompt()).is_empty());
        assert!(window.wizard().expect("open").options.admin);
        assert!(window.click("Back").is_empty());
        assert_eq!(window.step(), Some(Step::Options));
        assert!(window.click("View only").is_empty());
        let sent = window.click("Continue");
        let Some(Action::Manager(ManagerOp::Preview(choice))) = sent.first() else {
            panic!("no preview asked: {sent:?}");
        };
        assert_eq!(window.step(), Some(Step::Check), "no ⑤a");
        assert_eq!(choice.options.elevation, None, "the level went");
    }

    /// §B.8.7.1: on Linux the step is absent and ⑤ says the plan's sentence
    /// in its place; on Windows facts the sentence is not shown.
    #[test]
    fn the_linux_wizard_says_the_planned_sentence() {
        let mut window = at_options("My machines", false);
        window.model.wizard.account = Some(AccountFacts::Linux);
        window.pass(Vec::new());
        assert!(window.has_text(LINUX_SENTENCE));
        let sent = window.click("Continue");
        let Some(Action::Manager(ManagerOp::Preview(choice))) = sent.first() else {
            panic!("no preview asked: {sent:?}");
        };
        assert_eq!(choice.options.elevation, None);
        assert_eq!(window.step(), Some(Step::Check), "no ⑤a");
        let mut window = at_options("My machines", false);
        window.model.wizard.account = Some(windows_admin());
        window.pass(Vec::new());
        assert!(!window.has_text(LINUX_SENTENCE));
    }

    /// Decision M1-67, §B.8.7.1: with the level on, ⑤a shows its warning
    /// and the grant's block window, and its Continue opens ④ again with a
    /// new passphrase and the new-grant line under it, offering no own
    /// password; from there the grant goes out with the level and the
    /// generated password. With the level off ④ never shows the line.
    #[test]
    fn the_new_grant_line_shows_under_the_password() {
        let new_grant = NEW_GRANT_LINE.replace("<device>", "Office laptop");
        let (mut window, probe) = continue_from_options("My machines", Some(windows_admin()));
        judge(&mut window, &probe, Some(true), None);
        let shown_before = window.phrase();
        assert!(window.click(&prompt()).is_empty());
        assert!(window.wizard().expect("open").options.admin);
        assert!(window.has_text(&ADMINISTRATOR_WARNING.replace("<device>", "Office laptop")));
        assert!(window.has_text("Time to stop a connection: 3 s"));
        assert!(
            window.click("Continue").is_empty(),
            "④ again, nothing asked"
        );
        assert_eq!(window.step(), Some(Step::Password));
        assert!(window.has_text(&new_grant), "the line under the passphrase");
        assert_ne!(window.phrase(), shown_before, "a new passphrase");
        assert!(!window.has_control(USE_MY_OWN), "the generator's only");
        assert!(window.click("Continue").is_empty());
        assert_eq!(window.step(), Some(Step::Options));
        let sent = window.click("Continue");
        assert_eq!(
            sent,
            vec![Action::Manager(ManagerOp::Preview(Box::new(probe.clone())))]
        );
        judge(&mut window, &probe, Some(true), None);
        assert_eq!(window.step(), Some(Step::Administrator));
        assert!(window.wizard().expect("open").options.admin, "still on");
        let sent = window.click("Continue");
        let Some(Action::Manager(ManagerOp::Preview(choice))) = sent.first() else {
            panic!("no preview asked: {sent:?}");
        };
        let choice = (**choice).clone();
        assert_eq!(choice.options.elevation, Some(Elevation::Admin));
        judge(&mut window, &choice, Some(true), None);
        assert_eq!(window.step(), Some(Step::Check));
        assert!(window.click("Continue").is_empty());
        let sent = grants(&window.click(TURN_ON));
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].choice, choice);
        assert!(matches!(sent[0].password, NewPassword::Generated(_)));
        let window = at_password(WIDE, Some(false));
        assert!(!window.has_text(&new_grant));
    }

    /// §B.8.7.4: where the guard's preview refuses the level (Helping
    /// someone, a standard account, a copy outside Program Files), ⑤a says
    /// the guard's reason and offers no switch; Continue goes on without the
    /// level.
    #[test]
    fn a_refused_level_shows_its_reason_and_no_switch() {
        use tornect_core::levels::{
            REFUSAL_ADMIN_HELPING_SOMEONE, REFUSAL_ADMIN_STANDALONE, REFUSAL_ADMIN_STANDARD_ACCOUNT,
        };
        for (preset, why) in [
            ("Helping someone", REFUSAL_ADMIN_HELPING_SOMEONE),
            ("My machines", REFUSAL_ADMIN_STANDARD_ACCOUNT),
            ("My machines", REFUSAL_ADMIN_STANDALONE),
        ] {
            let (mut window, probe) = continue_from_options(preset, Some(windows_admin()));
            judge(&mut window, &probe, None, Some(why));
            assert!(window.has_text(why), "{why}");
            assert!(!window.has_control(&prompt()), "{why}: no switch");
            let sent = window.click("Continue");
            let Some(Action::Manager(ManagerOp::Preview(choice))) = sent.first() else {
                panic!("{why}: no preview asked: {sent:?}");
            };
            assert_eq!(choice.options.elevation, None, "{why}");
            assert_eq!(window.step(), Some(Step::Check), "{why}");
        }
    }

    // ------------------------------------------------------------ the raise and the restore (§B.8.7.1)

    use super::super::super::super::model::GrantLevel;

    /// No level, no mark, *My machines*.
    fn plain() -> GrantLevel {
        GrantLevel {
            holds: false,
            marked: false,
            preset: Preset::MyMachines,
        }
    }

    /// The window host with `device(1)`'s control grant in `state`, its
    /// level and mark `level`, on Windows facts.
    fn with_a_level(state: &str, level: GrantLevel) -> Model {
        let mut model = with_a_grant(SessionMode::Control);
        if let Some(manager) = model.manager.as_mut() {
            manager.grants[0].state = state.to_owned();
        }
        model.wizard.levels = vec![(device(1), level)];
        model.wizard.account = Some(windows_admin());
        model
    }

    /// "Give administrator access…" on the row: the raise's step, and the
    /// preview it asked for.
    fn at_raise() -> (Window, WizardChoice) {
        let mut window = Window::new(with_a_level("active", plain()), WIDE);
        let sent = window.click(RAISE);
        let Some(Action::Manager(ManagerOp::Preview(choice))) = sent.first() else {
            panic!("no preview asked: {sent:?}");
        };
        let choice = (**choice).clone();
        assert_eq!(window.step(), Some(Step::Raise));
        (window, choice)
    }

    /// Decision M1-67, §B.8.7.1: the raise from the manager asks the guard's
    /// preview of the level alone; until it answers no passphrase is shown
    /// and Continue sends nothing; then the plan's two lines and the
    /// passphrase, and no own password; Continue sends that generated
    /// passphrase with the level in one registration and keeps no copy. The
    /// row offers no raise where the level does not exist (Linux facts, none
    /// read), where the grant holds it, or for *Helping someone*.
    #[test]
    fn the_raise_cannot_finish_without_the_new_password() {
        let (mut window, choice) = at_raise();
        assert_eq!(
            choice.options,
            GrantOptions {
                elevation: Some(Elevation::Admin),
                ..GrantOptions::default()
            },
            "the level alone"
        );
        assert!(
            window.click("Continue").is_empty(),
            "not before the preview"
        );
        judge(&mut window, &choice, Some(true), None);
        assert!(window.has_text(&RAISE_LINE.replace("<device>", "Office laptop")));
        assert!(window.has_text(&NEW_GRANT_LINE.replace("<device>", "Office laptop")));
        assert!(!window.has_control(USE_MY_OWN));
        let shown = window.phrase();
        let sent = window.click("Continue");
        let [Action::Manager(ManagerOp::ChangePassword(request))] = sent.as_slice() else {
            panic!("one registration: {sent:?}");
        };
        assert_eq!(request.choice, choice);
        assert!(
            matches!(&request.password, NewPassword::Generated(p) if p.0.as_str() == shown),
            "the passphrase shown, as generated"
        );
        assert!(
            window.wizard().is_some_and(|w| w.passphrase.is_none()),
            "no copy"
        );
        for (account, level) in [
            (Some(AccountFacts::Linux), plain()),
            (None, plain()),
            (
                Some(windows_admin()),
                GrantLevel {
                    holds: true,
                    ..plain()
                },
            ),
            (
                Some(windows_admin()),
                GrantLevel {
                    preset: Preset::HelpingSomeone,
                    ..plain()
                },
            ),
        ] {
            let mut model = with_a_level("active", level);
            model.wizard.account = account;
            let window = Window::new(model, WIDE);
            assert!(!window.has_control(RAISE), "{account:?} {level:?}");
        }
    }

    /// §B.8.7.1 ⑤a's warning where the level is given: the raise draws it,
    /// with the device's label, above the raise's sentence once the guard's
    /// preview has judged the level and did not refuse it; the restore keeps
    /// its own sentence only.
    #[test]
    fn the_raise_shows_the_administrator_warning() {
        let warning = ADMINISTRATOR_WARNING.replace("<device>", "Office laptop");
        let raise = RAISE_LINE.replace("<device>", "Office laptop");
        let top = |window: &Window, text: &str| {
            window
                .nodes
                .iter()
                .find(|n| n.value().is_some_and(|v| v.contains(text)))
                .and_then(Node::bounds)
                .map(|b| b.y0)
                .expect("drawn")
        };
        let (mut window, choice) = at_raise();
        assert!(!window.has_text(&warning), "not before the preview");
        judge(&mut window, &choice, Some(true), None);
        assert!(window.has_text(&warning));
        assert!(top(&window, &warning) < top(&window, &raise), "above");
        let (mut window, choice) = at_raise();
        let why = tornect_core::levels::REFUSAL_ADMIN_STANDARD_ACCOUNT;
        judge(&mut window, &choice, None, Some(why));
        assert!(!window.has_text(&warning), "refused");
        let marked = GrantLevel {
            holds: true,
            marked: true,
            ..plain()
        };
        let mut window = Window::new(with_a_level("disabled:restore", marked), WIDE);
        assert!(window.click("Enable").is_empty());
        assert!(window.has_text(&RESTORE_LINE.replace("<device>", "Office laptop")));
        assert!(!window.has_text(&warning), "the restore");
    }

    /// §B.8.7.1 ⑤ for *Headless box*: the plan's statement is drawn, and with
    /// no time to stop a connection Continue does nothing until "I
    /// understand" is ticked; at 1 s no tick is needed; *My machines* shows
    /// neither.
    #[test]
    fn headless_box_says_its_statement_and_needs_the_tick_at_0_s() {
        let mut window = at_options("Headless box", false);
        assert_eq!(window.wizard().map(|w| w.options.block_window_s), Some(0));
        assert!(window.has_text(HEADLESS_STATEMENT));
        assert!(window.has_control(I_UNDERSTAND));
        assert!(window.click("Continue").is_empty(), "not before the tick");
        assert_eq!(window.step(), Some(Step::Options));
        assert!(window.click(I_UNDERSTAND).is_empty());
        let sent = window.click("Continue");
        assert!(
            matches!(sent.first(), Some(Action::Manager(ManagerOp::Preview(_)))),
            "{sent:?}"
        );
        assert_eq!(window.step(), Some(Step::Check));
        let mut window = at_options("Headless box", false);
        options_mut(&mut window).block_window_s = 1;
        window.pass(Vec::new());
        assert!(window.has_text(HEADLESS_STATEMENT));
        assert!(!window.has_control(I_UNDERSTAND), "1 s: no tick");
        let sent = window.click("Continue");
        assert!(
            matches!(sent.first(), Some(Action::Manager(ManagerOp::Preview(_)))),
            "{sent:?}"
        );
        let window = at_options("My machines", false);
        assert!(!window.has_text(HEADLESS_STATEMENT));
        assert!(!window.has_control(I_UNDERSTAND));
    }

    /// §B.8.7.1 ④ where control here reaches programs that run as
    /// administrator: while the guard's preview of this choice says only a
    /// generated password will do, ④ says why above the passphrase, with the
    /// device's label, and offers no own password; while the preview is
    /// pending, could not judge, or allows an own password, it does not.
    #[test]
    fn the_password_step_says_why_the_password_is_generated() {
        let why = GENERATED_ONLY.replace("<device>", "Office laptop");
        let top = |window: &Window, text: &str| {
            window
                .nodes
                .iter()
                .find(|n| n.value().is_some_and(|v| v.contains(text)))
                .and_then(Node::bounds)
                .map(|b| b.y0)
                .expect("drawn")
        };
        let mut window = at_password(WIDE, Some(true));
        assert!(window.has_text(&why));
        assert!(!window.has_control(USE_MY_OWN));
        let phrase = window.phrase();
        assert!(
            top(&window, &why) < top(&window, &phrase),
            "above the passphrase"
        );
        window.model.wizard.preview = None;
        window.pass(Vec::new());
        assert!(!window.has_text(&why), "pending");
        for judged in [None, Some(false)] {
            let window = at_password(WIDE, judged);
            assert!(!window.has_text(&why), "{judged:?}");
        }
    }

    /// §B.8.7.1: the raise offers Cancel first, then Continue: Cancel is on
    /// the left and in the key order, Continue is not in it (a pointer click
    /// only); Cancel closes the step and sends nothing. A refused level
    /// shows the guard's reason and only Cancel.
    #[test]
    fn the_raise_offers_cancel_first() {
        let (mut window, choice) = at_raise();
        judge(&mut window, &choice, Some(true), None);
        assert!(window.center("Cancel").x < window.center("Continue").x);
        assert!(
            window
                .node("Cancel")
                .supports_action(egui::accesskit::Action::Focus)
        );
        assert!(
            !window
                .node("Continue")
                .supports_action(egui::accesskit::Action::Focus),
            "pointer only"
        );
        assert!(window.click("Cancel").is_empty());
        assert!(window.wizard().is_none(), "closed");
        let (mut window, choice) = at_raise();
        let why = tornect_core::levels::REFUSAL_ADMIN_STANDARD_ACCOUNT;
        judge(&mut window, &choice, None, Some(why));
        assert!(window.has_text(why));
        assert!(!window.has_control("Continue"));
        assert!(window.has_control("Cancel"));
    }

    /// M-UI-3's rule on the raise: no run of Tabs followed by Enter or Space
    /// sends its registration; the click on Continue does.
    #[test]
    fn no_key_continues_the_raise() {
        let raised = |actions: &[Action]| {
            actions
                .iter()
                .any(|a| matches!(a, Action::Manager(ManagerOp::ChangePassword(_))))
        };
        // Past the sidebar and the section list to every button of the step.
        for tabs in 0..=20 {
            for key in [egui::Key::Enter, egui::Key::Space] {
                let (mut window, choice) = at_raise();
                judge(&mut window, &choice, Some(true), None);
                let mut sent = Vec::new();
                for _ in 0..tabs {
                    sent.extend(window.key(egui::Key::Tab));
                }
                sent.extend(window.key(key));
                assert!(!raised(&sent), "{tabs} tabs {key:?}: {sent:?}");
            }
        }
        let (mut window, choice) = at_raise();
        judge(&mut window, &choice, Some(true), None);
        assert!(raised(&window.click("Continue")));
    }

    /// §B.8.6.1, decision M1-67: *Enable* on a disabled grant that holds the
    /// level with its password marked sends no enable: the restore's step
    /// opens with the plan's sentence and a generated passphrase, and its
    /// Continue sends that passphrase with no option change, the enable to
    /// follow it; an unmarked grant at the level, or a marked one without
    /// it, is enabled at once.
    #[test]
    fn enabling_a_marked_grant_asks_for_a_new_password_first() {
        let marked = GrantLevel {
            holds: true,
            marked: true,
            ..plain()
        };
        let mut window = Window::new(with_a_level("disabled:restore", marked), WIDE);
        assert!(window.click("Enable").is_empty(), "no enable yet");
        assert_eq!(window.step(), Some(Step::Restore));
        assert!(window.has_text(&RESTORE_LINE.replace("<device>", "Office laptop")));
        let shown = window.phrase();
        for key in [egui::Key::Enter, egui::Key::Space] {
            assert!(window.key(key).is_empty(), "{key:?}");
        }
        let sent = window.click("Continue");
        let [Action::Manager(ManagerOp::Restore(request))] = sent.as_slice() else {
            panic!("one restore: {sent:?}");
        };
        assert_eq!(request.choice, no_change());
        assert!(matches!(&request.password, NewPassword::Generated(p) if p.0.as_str() == shown));
        for level in [
            GrantLevel {
                holds: true,
                ..plain()
            },
            GrantLevel {
                marked: true,
                ..plain()
            },
        ] {
            let mut window = Window::new(with_a_level("disabled:restore", level), WIDE);
            assert_eq!(
                window.click("Enable"),
                vec![Action::Manager(ManagerOp::Enable(device(1)))],
                "{level:?}"
            );
        }
    }

    /// §B.8.6.2: ⑦ says, while a pause runs, that the device can connect only
    /// once it ends; without a pause it says nothing of one.
    #[test]
    fn the_summary_says_a_running_pause() {
        let paused = PAUSED_SUMMARY.replace("<device>", "Office laptop");
        for pause in [None, Some(u64::MAX)] {
            let mut window = at_password(WIDE, Some(false));
            if let Some(manager) = window.model.manager.as_mut() {
                manager.on = true;
                manager.paused_until = pause;
            }
            to_summary(&mut window);
            assert_eq!(window.has_text(&paused), pause.is_some(), "{pause:?}");
        }
    }

    /// §B.8.6.1: a restore whose new password was set but whose *Enable* was
    /// refused ends with the sentence that says so, and with no new
    /// passphrase (the password set stays the grant's).
    #[test]
    fn a_restore_whose_enable_was_refused_asks_for_no_other_password() {
        let marked = GrantLevel {
            holds: true,
            marked: true,
            ..plain()
        };
        let mut window = Window::new(with_a_level("disabled:restore", marked), WIDE);
        assert!(window.click("Enable").is_empty(), "no enable yet");
        window.phrase();
        let sent = window.click("Continue");
        let [Action::Manager(ManagerOp::Restore(request))] = sent.as_slice() else {
            panic!("one restore: {sent:?}");
        };
        window.model.wizard.answer = Some((request.attempt, WizardAnswer::SetNotEnabled));
        window.pass(Vec::new());
        window.pass(Vec::new());
        assert_eq!(window.step(), Some(Step::Restore));
        assert!(window.has_text(&RESTORED_NOT_ENABLED.replace("<device>", "Office laptop")));
        let w = window.wizard().expect("open");
        assert!(w.passphrase.is_none(), "no new passphrase");
        assert!(!window.has_control("Continue"));
    }

    // ------------------------------------------------------------ ⑤a's offer (§B.8.7.1)

    /// Two other control grants the change made reach the level: "Laptop A"
    /// marked, "Desk B" not.
    fn reaching() -> Vec<NewlyReaching> {
        vec![
            NewlyReaching {
                device: device(2),
                label: "Laptop A".to_owned(),
                marked: true,
            },
            NewlyReaching {
                device: device(3),
                label: "Desk B".to_owned(),
                marked: false,
            },
        ]
    }

    /// ⑦'s Turn on answered Done, the change having made `reaching` reach
    /// the level (the tokio side lists them): the wizard at the offer.
    fn at_offer(reaching: Vec<NewlyReaching>) -> Window {
        let mut window = at_summary(WIDE);
        let sent = grants(&window.click(TURN_ON));
        assert_eq!(sent.len(), 1);
        window.model.wizard.answer = Some((sent[0].attempt, WizardAnswer::Done));
        window.model.wizard.reaching = reaching;
        window.pass(Vec::new());
        assert_eq!(window.step(), Some(Step::Offer));
        window
    }

    /// §B.8.7.1 ⑤a, decision M1-67: a raise whose wizard closed while its
    /// dialog was open (the window left Settings) still opens the offer
    /// once its Done comes, having made other control grants reach the
    /// level, the next time Security is drawn; a Done with none to name
    /// opens nothing.
    #[test]
    fn a_done_after_the_wizard_closed_opens_the_offer() {
        for (listed, offered) in [(reaching(), true), (Vec::new(), false)] {
            let (mut window, choice) = at_raise();
            judge(&mut window, &choice, Some(true), None);
            let sent = window.click("Continue");
            let [Action::Manager(ManagerOp::ChangePassword(request))] = sent.as_slice() else {
                panic!("one registration: {sent:?}");
            };
            let attempt = request.attempt;
            window.form.page = Page::Home;
            window.pass(Vec::new());
            assert!(window.wizard().is_none(), "closed with the page");
            window.model.wizard.answer = Some((attempt, WizardAnswer::Done));
            window.model.wizard.reaching = listed;
            window.pass(Vec::new());
            window.form.page = Page::Settings;
            window.pass(Vec::new());
            window.pass(Vec::new());
            assert_eq!(
                window.has_text(&OFFER_HEADING.replace("<labels>", "Laptop A, Desk B")),
                offered
            );
            assert_eq!(window.step() == Some(Step::Offer), offered);
            assert_eq!(window.form.settings.pending, None, "the wait ended");
        }
    }

    /// The registrations among `actions`.
    fn renewals(actions: &[Action]) -> Vec<GrantRequest> {
        actions
            .iter()
            .filter_map(|a| match a {
                Action::Manager(ManagerOp::ChangePassword(request)) => Some((**request).clone()),
                _ => None,
            })
            .collect()
    }

    /// §B.8.7.1 ⑤a, decision M1-67: after a change that made other control
    /// grants reach the level the wizard does not close: the offer names them
    /// by their pinned labels under the plan's heading, "Give them new
    /// passwords now" ticked; an answer with none to name closes it.
    #[test]
    fn the_offer_lists_the_newly_reaching_devices_by_label() {
        let window = at_offer(reaching());
        assert!(window.has_text(&OFFER_HEADING.replace("<labels>", "Laptop A, Desk B")));
        assert!(window.has_control(GIVE_NEW));
        assert!(
            window
                .wizard()
                .and_then(|w| w.offer.as_ref())
                .is_some_and(|o| o.give),
            "ticked"
        );
        let mut window = at_summary(WIDE);
        let sent = grants(&window.click(TURN_ON));
        window.model.wizard.answer = Some((sent[0].attempt, WizardAnswer::Done));
        window.pass(Vec::new());
        assert!(window.wizard().is_none(), "none to name: closed");
    }

    /// The operator's ruling (b) of 2026-10-02, §B.8.6.1: unticked, the offer
    /// names only the devices whose password is marked, in the plan's line,
    /// and its Continue closes with nothing sent; with none marked there is
    /// no line.
    #[test]
    fn the_unticked_line_names_only_marked_devices() {
        let mut window = at_offer(reaching());
        let marked_line = UNTICKED_LINE.replace("<labels>", "Laptop A");
        assert!(!window.has_text(&marked_line), "not while ticked");
        assert!(window.click(GIVE_NEW).is_empty());
        assert!(window.has_text(&marked_line));
        assert!(!window.has_text("Desk B get view only"));
        assert!(window.click("Continue").is_empty(), "nothing sent");
        assert!(window.wizard().is_none());
        let unmarked = reaching()
            .into_iter()
            .map(|d| NewlyReaching { marked: false, ..d })
            .collect();
        let mut window = at_offer(unmarked);
        assert!(window.click(GIVE_NEW).is_empty());
        assert!(!window.has_text("get view only"));
    }

    /// §B.8.7.1: each device's new password is its own prompt: a new
    /// passphrase, shown once, and *Change password*, which sends one
    /// registration for that device alone, its passphrase as generated and no
    /// option change; the next device gets another passphrase.
    #[test]
    fn each_new_password_is_its_own_registration() {
        let mut window = at_offer(reaching());
        assert!(window.click("Continue").is_empty());
        let mut seen: Vec<String> = Vec::new();
        for (d, label) in [(device(2), "Laptop A"), (device(3), "Desk B")] {
            assert!(
                window.has_text(&format!("New password for {label}")),
                "{label}"
            );
            let shown = window.phrase();
            let sent = renewals(&window.click(CHANGE_PASSWORD));
            assert_eq!(sent.len(), 1, "{label}");
            assert_eq!(sent[0].choice.device, d);
            assert_eq!(sent[0].choice.options, GrantOptions::default());
            assert!(
                matches!(&sent[0].password, NewPassword::Generated(p) if p.0.as_str() == shown),
                "{label}"
            );
            assert!(!seen.contains(&shown), "{label}: a passphrase of its own");
            seen.push(shown);
            window.model.wizard.answer = Some((sent[0].attempt, WizardAnswer::Done));
            window.pass(Vec::new());
        }
        assert!(
            window.wizard().is_none(),
            "every device has its new password"
        );
    }

    /// §B.8.7.1, §B.8.7.4: a prompt that does not finish (its dialog
    /// refused, or Cancel) leaves that device on its old password; once the
    /// round is over the step lists those devices again under the command
    /// line's sentence, ticked, and asks for them again.
    #[test]
    fn a_cancelled_prompt_lists_the_remaining_devices() {
        let mut window = at_offer(reaching());
        assert!(window.click("Continue").is_empty());
        let first = renewals(&window.click(CHANGE_PASSWORD));
        assert_eq!(first.len(), 1);
        window.model.wizard.answer = Some((
            first[0].attempt,
            WizardAnswer::Refused("Not done: this computer's password was not confirmed."),
        ));
        window.pass(Vec::new());
        assert!(window.has_text("New password for Desk B"));
        let second = renewals(&window.click(CHANGE_PASSWORD));
        assert_eq!(second.len(), 1);
        window.model.wizard.answer = Some((second[0].attempt, WizardAnswer::Done));
        window.pass(Vec::new());
        assert!(window.has_text(&STILL_OLD.replace("<labels>", "Laptop A")));
        assert!(
            window
                .wizard()
                .and_then(|w| w.offer.as_ref())
                .is_some_and(|o| o.give && o.queue.len() == 1)
        );
        assert!(window.click("Continue").is_empty());
        assert!(window.has_text("New password for Laptop A"));
        assert!(window.click("Cancel").is_empty());
        assert!(window.has_text(&STILL_OLD.replace("<labels>", "Laptop A")));
    }

    /// M-UI-3's rule on the offer's prompts: no run of Tabs followed by
    /// Enter or Space sends a registration.
    #[test]
    fn no_key_completes_an_offer_prompt() {
        // Past the sidebar and the section list to every button of the step.
        for tabs in 0..=20 {
            for key in [egui::Key::Enter, egui::Key::Space] {
                let mut window = at_offer(reaching());
                assert!(window.click("Continue").is_empty());
                let mut sent = Vec::new();
                for _ in 0..tabs {
                    sent.extend(window.key(egui::Key::Tab));
                }
                sent.extend(window.key(key));
                assert!(renewals(&sent).is_empty(), "{tabs} tabs {key:?}: {sent:?}");
            }
        }
    }

    // ------------------------------------------------------------ the turn-off (§B.8.7.1 ⑤a)

    /// §B.8.7.1 ⑤a, decision M1-68: "Turn administrator access off" on the
    /// row of a grant that holds the level sends the turn-off at once (no
    /// step); the row then says the command line's turn-off sentence and,
    /// where control still reaches the level, its condition, ending "To stop
    /// that now, disable <device>."; a grant without the level offers none.
    #[test]
    fn the_turn_off_line_carries_its_condition() {
        use super::super::security::LEVEL_OFF_BUTTON;
        use crate::unattended::{LEVEL_OFF, LEVEL_OFF_ANOTHER_GRANT, LEVEL_OFF_HELPER_TASK};
        use tornect_core::unattended::ipc::SetLevelNonePayload;
        let at_level = GrantLevel {
            holds: true,
            ..plain()
        };
        let mut window = Window::new(with_a_level("active", at_level), WIDE);
        assert_eq!(
            window.click(LEVEL_OFF_BUTTON),
            vec![Action::Manager(ManagerOp::LevelOff(device(1)))]
        );
        assert!(window.wizard().is_none(), "no step");
        let window = Window::new(with_a_level("active", plain()), WIDE);
        assert!(
            !window.has_control(LEVEL_OFF_BUTTON),
            "no level, no turn-off"
        );
        let off = LEVEL_OFF.replace("<device>", "Office laptop");
        for (keeps, condition) in [
            (SetLevelNonePayload::NOTHING, None),
            (
                SetLevelNonePayload::ANOTHER_ADMIN_GRANT,
                Some(LEVEL_OFF_ANOTHER_GRANT),
            ),
            (
                SetLevelNonePayload::HELPER_TASK,
                Some(LEVEL_OFF_HELPER_TASK),
            ),
        ] {
            let mut model = with_a_level("active", plain());
            model.wizard.level_off = Some((device(1), keeps));
            let window = Window::new(model, WIDE);
            assert!(window.has_text(&off), "{keeps}");
            for text in [LEVEL_OFF_ANOTHER_GRANT, LEVEL_OFF_HELPER_TASK] {
                let said = window.has_text(&text.replace("<device>", "Office laptop"));
                assert_eq!(said, condition == Some(text), "{keeps}");
            }
            assert_eq!(
                window.has_text("To stop that now, disable Office laptop."),
                condition.is_some(),
                "{keeps}"
            );
        }
    }
}
