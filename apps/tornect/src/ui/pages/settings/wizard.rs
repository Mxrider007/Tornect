//! The grant wizard of Settings, Security (§B.8.7.1 ① to ⑦, without ⑤a): it gives
//! one paired device unattended access. ① says what that means, the scam
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
//! non-zero takes an own password back to ④'s generator. ⑥ shows this
//! computer's readiness rows; a red one needs "Enable anyway". ⑦ sums it up,
//! and *Turn on* sends it as one operation, which the tokio side runs
//! through the guard; the wizard changes only on its answer. ④ and ⑦
//! complete by a primary pointer click only. Every password and passphrase
//! is dropped (wiped) on Cancel, Back, close and once sent. While this screen
//! is shared the wizard closes (the section shows the hidden card).

use std::time::{Duration, Instant};

use egui::{RichText, Ui};
use tornect_core::DeviceId;
use tornect_core::session_log::SessionMode;
use tornect_core::unattended::grant::{MAX_BLOCK_WINDOW_S, Preset};
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
    to this computer without anyone here accepting: it needs that device and the password you \
    set now.";

/// The scam step (§B.8.7.1 ①).
pub(in super::super) const SCAM: &str = "Did someone call and ask you to set this up? Hang up.";

/// This system's limits (§B.8.8), on Linux.
pub(in super::super) const LIMITS_LINUX: [&str; 2] = [
    "While this computer is locked, a session shows no picture and takes no input: GNOME closes \
     remote access while the screen is locked, and it cannot be unlocked from another device.",
    "At the login screen, before anyone signs in, there is nothing to connect to.",
];

/// This system's limits (§B.8.8), on Windows.
pub(in super::super) const LIMITS_WINDOWS: [&str; 2] = [
    "While this computer is locked or signed out, a session shows no picture and takes no \
     input, and it cannot be unlocked from another device: that needs a system service, \
     planned after this release.",
    "A session's clicks and keys do not reach programs that run as administrator or Windows' \
     prompts for an administrator, and nothing says so.",
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
pub(in super::super) const GENERATED_ESTIMATE: &str = "Offline guessing estimate: about 900 \
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
    limited only by the lifetime budget, at most 60 failed attempts until you unlock it here plus \
    about 52 a year, at most 24 a day (about 33 on the first day), and by the notifications.";

/// An expiry of "never" (§B.8.6.1).
pub(in super::super) const NEVER_WARNING: &str = "Access that never ends stays until you remove \
    it, also if that device is lost or you forget it.";

/// Lock-on-disconnect, where this computer cannot be unlocked from another
/// device (§B.8.8: Windows and GNOME).
pub(in super::super) const LOCK_WARNING: &str = "Once this computer locks, no session can see or \
    use it until someone here unlocks it.";

/// Where ⑤ sends the host-wide options.
pub(in super::super) const HOST_WIDE: &str = "Set on the Security page for every device.";

/// ⑦, while unattended access is off: two dialogs follow.
pub(in super::super) const ASKS_TWICE: &str = "You are asked for your password once to give \
    access, and once more to turn unattended access on.";

/// `G_NEEDS_PASSWORD` at *Turn on*: a raise appeared while the person was
/// asked (decision M1-67).
pub(in super::super) const NEEDS_GENERATED: &str = "Something changed while you were asked: this \
    device now needs a new generated password. Nothing was saved.";

/// The commit of ⑦.
pub(in super::super) const TURN_ON: &str = "Turn on";

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
    /// ⑥ This computer's readiness.
    Check,
    /// ⑦ What is given, and *Turn on*.
    Summary,
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
            Self::Check => "Check this computer",
            Self::Summary => "Summary",
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
    /// Only while nobody is at this computer.
    pub(in super::super) require_absent: bool,
    /// Pictures and input through Tor only.
    pub(in super::super) require_tor_only: bool,
    /// Lock this computer when a session ends.
    pub(in super::super) lock_on_disconnect: bool,
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
            require_absent: false,
            require_tor_only: false,
            lock_on_disconnect: d.lock_on_disconnect,
        }
    }
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
    /// Something changed while the person was asked: from then on the
    /// password can only be generated.
    pub(in super::super) generated_only: bool,
    /// Why the last *Turn on* saved nothing.
    pub(in super::super) note: Option<&'static str>,
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
            passphrase: None,
            own: false,
            typed: room(),
            again: room(),
            attempt: None,
            generated_only: false,
            note: None,
        }
    }

    /// What ②, ③ and ⑤ chose: every option goes into the one registration.
    fn choice(&self) -> Option<WizardChoice> {
        let o = self.options;
        Some(WizardChoice {
            device: self.device?,
            preset: self.preset,
            options: GrantOptions {
                mode: Some(o.mode),
                expires_at: o.never.then_some(0),
                block_window_s: Some(o.block_window_s),
                ask_before_start: Some(o.ask_before_start),
                require_absent: Some(o.require_absent),
                require_tor_only: Some(o.require_tor_only),
                lock_on_disconnect: Some(o.lock_on_disconnect),
                hard_lock_after: Some(o.hard_lock_after),
                waive_attended_precondition: self.waive,
                ..GrantOptions::default()
            },
        })
    }

    /// Go to ④ with a new passphrase and no own password: every earlier
    /// one is wiped.
    fn open_password(&mut self) {
        self.step = Step::Password;
        self.passphrase = generated();
        self.drop_own();
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
        match answer {
            WizardAnswer::Done => {
                form.wizard = None;
                return;
            }
            WizardAnswer::NeedsGenerated => {
                w.generated_only = true;
                w.note = Some(NEEDS_GENERATED);
                w.open_password();
            }
            WizardAnswer::Refused(why) => {
                w.note = Some(why);
                w.open_password();
            }
        }
    }
    ui.add_space(4.0);
    ui.label(
        RichText::new(w.step.title())
            .font(theme::font(ui.ctx(), Face::Semibold, 17.0))
            .color(t.text_primary),
    );
    ui.add_space(6.0);
    let mut close = false;
    match w.step {
        Step::Before => before(ui, t, w, &mut close),
        Step::Device => device(ui, t, model, w, &mut close),
        Step::Preset => preset(ui, t, w, &mut close, actions),
        Step::Password => password_step(ui, t, model, w, &mut close),
        Step::Options => options(ui, t, model, manager, w, &mut close, actions),
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

/// ⑤'s choices as ⑦ sums them up, in the words of the presets' lines.
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
    parts.push(match o.hard_lock_after {
        0 => "no hard lock".to_owned(),
        n => format!("hard lock after {n} failed attempts in a row"),
    });
    if o.require_absent {
        parts.push("only while nobody is using this computer".to_owned());
    }
    if o.require_tor_only {
        parts.push("pictures and input through Tor only".to_owned());
    }
    if o.lock_on_disconnect {
        parts.push("locks this computer when a session ends".to_owned());
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
/// reach stays 0.
fn password_step(ui: &mut Ui, t: &Tokens, model: &Model, w: &mut Wizard, close: &mut bool) {
    if let Some(note) = w.note {
        line(ui, note, t.danger_text);
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
    ui.add_space(10.0);
    ui.horizontal(|ui| {
        cancel(ui, true, close);
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
    ui.add_space(8.0);
    widgets::section_header(ui, "Hard lock after failed attempts in a row");
    ui.add(egui::Slider::new(
        &mut o.hard_lock_after,
        0..=tornect_core::unattended::grant::LIFETIME_BUDGET,
    ));
    if o.hard_lock_after == 0 {
        line(ui, HARD_LOCK_OFF, t.warn);
    }
    ui.add_space(8.0);
    widgets::section_header(ui, "When it connects");
    ui.checkbox(&mut o.ask_before_start, "Ask before starting");
    ui.checkbox(
        &mut o.require_absent,
        "Only while nobody is using this computer",
    );
    ui.checkbox(
        &mut o.require_tor_only,
        "Pictures and input through Tor only",
    );
    // Refused with Headless box (§B.8.7.1 ⑤): not offered there.
    if d.lock_on_disconnect_allowed {
        ui.checkbox(
            &mut o.lock_on_disconnect,
            "Lock this computer when a session ends",
        );
        if o.lock_on_disconnect {
            line(ui, LOCK_WARNING, t.warn);
        }
    } else {
        o.lock_on_disconnect = false;
    }
    ui.add_space(8.0);
    widgets::section_header(ui, "For every device");
    let state = |on: bool| if on { "on" } else { "off" };
    line(
        ui,
        &format!("Keep this computer awake: {}", state(manager.keep_awake)),
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
        if Button::new(Kind::Primary, "Continue")
            .small()
            .show(ui)
            .clicked()
            && let Some(choice) = w.choice()
        {
            actions.push(Action::Manager(ManagerOp::Preview(Box::new(choice))));
            w.step = Step::Check;
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
        "at least about 4 months"
    } else {
        "at least about 1.2 days"
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
    /// lock-on-disconnect with its warning, and not offered with Headless
    /// box; keep-awake and the idle lock shown as they are, set on the
    /// Security page only.
    #[test]
    fn each_option_keeps_its_planned_rule() {
        // My machines on an OS keychain: never, with its warning; the hard lock
        // off, warned; lock-on-disconnect, warned; the others as ticked.
        let mut window = at_options("My machines", false);
        assert!(!window.has_text(NEVER_WARNING));
        assert!(window.click("Never").is_empty());
        assert!(window.has_text(NEVER_WARNING));
        options_mut(&mut window).hard_lock_after = 0;
        window.pass(Vec::new());
        assert!(window.has_text(HARD_LOCK_OFF));
        assert!(
            window
                .click("Lock this computer when a session ends")
                .is_empty()
        );
        assert!(window.has_text(LOCK_WARNING));
        assert!(
            window
                .click("Only while nobody is using this computer")
                .is_empty()
        );
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
        assert_eq!(sent.lock_on_disconnect, Some(true));
        assert_eq!(sent.require_absent, Some(true));
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
                        Some(Step::Options) => 5,
                        Some(Step::Check) => 6,
                        Some(Step::Summary) => 7,
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
}
