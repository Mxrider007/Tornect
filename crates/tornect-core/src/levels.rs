//! Session levels (`docs/PLAN.md` §B.2.1, §B.8.4.1; decisions M1-64, M1-65,
//! M1-57): the administrator level a session carries beside its mode, the
//! §B.2.1 availability table — which answers a host sheet may offer on this
//! computer and the one sentence under them — and the clamp that fixes a
//! session's level at `SESSION_ACCEPT`.
//!
//! Pure data and pure functions. The facts come from `tornect-platform` (the
//! Windows registry and the process token; Linux has one row); the host FSM
//! in `tornect-signal` refuses an answer the table does not offer; the app
//! draws the sheet from an [`Availability`].

use crate::session_log::SessionMode;

/// The administrator level of a session (`SESSION_ACCEPT.elevation`,
/// `SESSION_REQUEST.unattended.want_elevation`; absent on the wire = none).
/// Ordered: [`Elevation::None`] is the more restrictive. In `sessions.log`
/// it is the optional field `elevation` (§B.8.13), written only as `admin`.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Default,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Elevation {
    /// The session acts as the signed-in user (the default).
    #[default]
    None,
    /// Windows: the remote's input also reaches programs running as
    /// administrator, for this session only (§B.2.1).
    Admin,
}

impl Elevation {
    /// The wire value (§B.8.4.1: `0` none, `1` admin).
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Admin => 1,
        }
    }

    /// From the wire value; `None` for anything but `0` or `1`.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::None),
            1 => Some(Self::Admin),
            _ => None,
        }
    }

    /// The more restrictive of two (§B.8.4.1: lower is the safe direction,
    /// never a reject).
    #[must_use]
    pub fn most_restrictive(a: Self, b: Self) -> Self {
        a.min(b)
    }
}

/// A session's level: its mode and its elevation. View-only never carries
/// an elevation (§B.8.4.1), so a [`Level`] cannot hold one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Level {
    mode: SessionMode,
    elevation: Elevation,
}

impl Level {
    /// View only.
    pub const VIEW_ONLY: Self = Self {
        mode: SessionMode::ViewOnly,
        elevation: Elevation::None,
    };
    /// Control as the signed-in user.
    pub const CONTROL: Self = Self {
        mode: SessionMode::Control,
        elevation: Elevation::None,
    };
    /// Control as administrator (Windows).
    pub const ADMIN: Self = Self {
        mode: SessionMode::Control,
        elevation: Elevation::Admin,
    };

    /// `mode` at `elevation`; view-only drops the elevation.
    #[must_use]
    pub fn new(mode: SessionMode, elevation: Elevation) -> Self {
        match mode {
            SessionMode::ViewOnly => Self::VIEW_ONLY,
            SessionMode::Control => Self { mode, elevation },
        }
    }

    /// The mode.
    #[must_use]
    pub const fn mode(self) -> SessionMode {
        self.mode
    }

    /// The elevation.
    #[must_use]
    pub const fn elevation(self) -> Elevation {
        self.elevation
    }

    /// The most restrictive of this level (a grant's, §B.8.4.1), what the
    /// request asked for, and what this host can deliver: each part lowered
    /// independently, never raised, never refused.
    #[must_use]
    pub fn clamp(self, want_mode: SessionMode, want: Elevation, deliverable: Elevation) -> Self {
        let mode = SessionMode::most_restrictive(self.mode, want_mode);
        let elevation = Elevation::most_restrictive(
            Elevation::most_restrictive(self.elevation, want),
            deliverable,
        );
        Self::new(mode, elevation)
    }
}

/// The rows of the §B.2.1 availability table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HostRow {
    /// Windows, installed in Program Files, UAC on (standard or administrator
    /// account).
    WindowsInstalled,
    /// Windows, standalone: run from any other folder (§B.1.1, M1-65).
    WindowsStandalone,
    /// Windows, UAC off (`EnableLUA` 0) on an administrator account, or the
    /// built-in Administrator without Admin Approval Mode
    /// (`FilterAdministratorToken` 0): every program runs as administrator.
    WindowsAlwaysAdministrator,
    /// Windows, a standard account where policy denies elevation
    /// (`ConsentPromptBehaviorUser` 0, or UAC off).
    WindowsPolicyDenies,
    /// Windows, an administrator account set to elevate without prompting
    /// (`ConsentPromptBehaviorAdmin` 0): any program there can become
    /// administrator without a prompt, so control is administrator access in
    /// effect, and the row offers View only and "Allow as administrator"
    /// with the Tornect confirmation, like the UAC-off row (the operator's
    /// ruling of 2026-09-29).
    WindowsAdminWithoutPrompt,
    /// Windows, the host itself started elevated while UAC is on: it refuses
    /// to open the onion service.
    WindowsStartedElevated,
    /// Linux, every desktop.
    Linux,
    /// Linux, the host itself running as root: it refuses to open the onion
    /// service (Tornect never runs as administrator on Linux).
    LinuxRoot,
    /// Windows, whether the host runs elevated could not be read: it refuses
    /// to open the onion service, as a host started elevated does.
    WindowsElevationUnreadable,
    /// Windows, the account's other facts could not be read (administrator,
    /// built-in Administrator, installed): View only alone.
    WindowsAccountUnreadable,
}

/// How the administrator answer is given on a row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdminPath {
    /// "Allow as administrator…": Windows shows its own prompt next, to start
    /// the administrator helper (§B.8.7.5, M-FEAT-3).
    WindowsPrompt,
    /// "Allow as administrator" (no "…"): no Windows prompt follows, so a
    /// Tornect confirmation does (Deny first, armed after 1 s).
    /// `needs_helper`: this host runs with a filtered token, so the level
    /// takes the administrator helper even without a prompt (M-FEAT-3).
    TornectConfirmation {
        /// Whether delivering it takes the administrator helper.
        needs_helper: bool,
    },
}

/// What a host sheet offers besides Deny, which is always offered and
/// always first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Answers {
    /// View only.
    pub view_only: bool,
    /// Allow: control as the signed-in user.
    pub allow: bool,
    /// Allow as administrator, and how.
    pub admin: Option<AdminPath>,
}

impl Answers {
    /// Nothing but Deny: a host that does not serve.
    pub const NONE: Self = Self {
        view_only: false,
        allow: false,
        admin: None,
    };

    /// Whether an answer at `level` is on offer. The person's answer is the
    /// level (§B.8.4.1: an attended session takes its level from the answer);
    /// one this set does not offer is refused, never lowered — an
    /// administrator answer never starts a session at a lower level (§B.2.1).
    #[must_use]
    pub fn offers(&self, level: Level) -> bool {
        match (level.mode(), level.elevation()) {
            (SessionMode::ViewOnly, _) => self.view_only,
            (SessionMode::Control, Elevation::None) => self.allow,
            (SessionMode::Control, Elevation::Admin) => self.admin.is_some(),
        }
    }

    /// The highest elevation of a control session on offer.
    #[must_use]
    pub fn deliverable(&self) -> Elevation {
        if self.admin.is_some() {
            Elevation::Admin
        } else {
            Elevation::None
        }
    }
}

/// Whether this build has the administrator helper (§B.8.7.5): M-FEAT-3.
/// Without it, an administrator answer that needs it — the Windows prompt
/// path and a filtered token without a prompt — is not offered. With it, the
/// host starts the helper between such an answer and its accept, and the
/// accept carries the administrator level only once the helper is connected
/// and checked (the helper itself: `tornect input-helper`, Windows only).
pub const ADMIN_HELPER: bool = false;

/// Under the buttons: a standalone copy (§B.2.1).
pub const SENTENCE_STANDALONE: &str =
    "Administrator access needs Tornect installed on this computer.";
/// Under the buttons: UAC off, or the built-in Administrator without Admin
/// Approval Mode.
pub const SENTENCE_ALWAYS_ADMINISTRATOR: &str = "Windows runs every program on this account as \
    administrator, so control always includes administrator access.";
/// Under the buttons: a standalone copy on an account where every program
/// runs as administrator — both sentences, as the table words them.
pub const SENTENCE_ALWAYS_ADMINISTRATOR_STANDALONE: &str = "Windows runs every program on this \
    account as administrator, so control always includes administrator access. Administrator \
    access needs Tornect installed on this computer.";
/// Under the buttons: policy denies elevation to a standard account.
pub const SENTENCE_POLICY_DENIES: &str =
    "This computer's policy does not let administrator access be given here.";
/// Why the host refuses to serve when it was started elevated with UAC on.
pub const SENTENCE_STARTED_ELEVATED: &str =
    "Start Tornect normally; administrator access is given per session.";
/// Under the buttons on Linux.
pub const SENTENCE_LINUX: &str = "On Linux, Tornect never runs as administrator. They can do what \
    you can do without a password; when the system asks for a password, they see that window and \
    can type into it.";
/// Added at every level when `PromptOnSecureDesktop` is 0.
pub const SENTENCE_SECURE_DESKTOP_OFF: &str =
    "Windows permission prompts appear on the shared screen here.";
/// The administrator line (under "Allow as administrator…").
pub const ADMIN_LINE: &str = "Windows asks you to confirm next. They can change anything on this \
    computer, including Tornect's settings and its log, and the changes stay after the session.";
/// The administrator line without its first sentence: where no Windows
/// prompt follows (the sentence of the no-prompt row, and the Tornect
/// confirmation's line).
pub const ADMIN_LINE_NO_PROMPT: &str = "They can change anything on this computer, including \
    Tornect's settings and its log, and the changes stay after the session.";
/// The line under "View only" (§B.2.1).
pub const LINE_VIEW_ONLY: &str = "They see this screen. They cannot type or click.";
/// The line under "Allow" on Windows (§B.2.1).
pub const LINE_ALLOW_WINDOWS: &str =
    "They can type and click as you. Programs running as administrator ignore their input.";
/// Under the buttons where the row's administrator answer needs the
/// administrator helper, which this build does not have ([`ADMIN_HELPER`]):
/// the answer is absent, and this says why.
pub const SENTENCE_NO_HELPER: &str =
    "Administrator access is not available in this version of Tornect.";
/// The line a session sheet shows after its administrator answer failed
/// (Windows' prompt cancelled or failed, or no helper to start): the other
/// answers stay open, and the popup's time keeps running (§B.2.1).
pub const SENTENCE_ADMIN_NOT_GIVEN: &str = "Administrator access was not given";
/// Why a Windows host that could not read whether it runs elevated refuses
/// to serve.
pub const SENTENCE_ELEVATION_UNREADABLE: &str = "Tornect could not read whether it runs as \
    administrator, so it does not accept connections. Start it again normally.";
/// Why a Windows host that could not read its account's facts offers View
/// only.
pub const SENTENCE_ACCOUNT_UNREADABLE: &str = "Tornect could not read this account's rights, so \
    it offers View only.";
/// Why a Linux host started as root refuses to serve (§B.2.1: on Linux
/// Tornect never runs as administrator).
pub const SENTENCE_LINUX_ROOT: &str = "Start Tornect as your own user; on Linux it never runs as \
    administrator.";

/// What the Windows probe read (`tornect-platform`). A registry value that
/// is absent is `None` and takes Windows' default (UAC's Group Policy
/// defaults: `EnableLUA` 1, `FilterAdministratorToken` 0,
/// `ConsentPromptBehaviorUser` 3, `ConsentPromptBehaviorAdmin` 5,
/// `PromptOnSecureDesktop` 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WindowsFacts {
    /// The executable lies under Program Files (installed, §B.1.1).
    pub installed: bool,
    /// `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`.
    pub enable_lua: Option<u32>,
    /// `…\FilterAdministratorToken` (Admin Approval Mode for the built-in
    /// Administrator).
    pub filter_administrator_token: Option<u32>,
    /// `…\ConsentPromptBehaviorUser` (0: deny elevation requests).
    pub consent_prompt_behavior_user: Option<u32>,
    /// `…\ConsentPromptBehaviorAdmin` (0: elevate without prompting).
    pub consent_prompt_behavior_admin: Option<u32>,
    /// `…\PromptOnSecureDesktop` (0: prompts on the user's desktop).
    pub prompt_on_secure_desktop: Option<u32>,
    /// The account is an administrator (counting the filtered token an
    /// administrator's programs get under UAC).
    pub administrator: bool,
    /// The account is the built-in Administrator (RID 500).
    pub builtin_administrator: bool,
    /// This process runs elevated: the full half of a split token
    /// (`TokenElevationTypeFull`).
    pub elevated: bool,
}

impl WindowsFacts {
    fn uac_on(&self) -> bool {
        self.enable_lua.unwrap_or(1) != 0
    }

    fn admin_approval_for_builtin(&self) -> bool {
        self.filter_administrator_token.unwrap_or(0) != 0
    }
}

/// The row of the §B.2.1 table this host is in: the answers its sheet
/// offers and the sentence under them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Availability {
    /// The row.
    pub row: HostRow,
    /// The answers the row gives (before [`ADMIN_HELPER`] is applied).
    pub answers: Answers,
    /// The one sentence under the buttons, if the row has one.
    pub sentence: Option<&'static str>,
    /// `PromptOnSecureDesktop` is 0: [`SENTENCE_SECURE_DESKTOP_OFF`] is
    /// added at every level.
    pub prompts_on_shared_screen: bool,
}

impl Availability {
    /// The Linux row: Deny · View only · Allow, and the Linux sentence.
    pub const LINUX: Self = Self {
        row: HostRow::Linux,
        answers: Answers {
            view_only: true,
            allow: true,
            admin: None,
        },
        sentence: Some(SENTENCE_LINUX),
        prompts_on_shared_screen: false,
    };

    /// A Linux host running as root: nothing to offer; it does not serve.
    pub const LINUX_ROOT: Self = Self {
        row: HostRow::LinuxRoot,
        answers: Answers::NONE,
        sentence: Some(SENTENCE_LINUX_ROOT),
        prompts_on_shared_screen: false,
    };

    /// The row of this host: `windows` holds what the Windows probe read,
    /// `None` on every other system (the Linux row).
    ///
    /// The rows are tested in this order, the first that holds wins:
    /// started elevated with UAC on (refuse); every program runs as
    /// administrator (UAC off on an administrator account, or the built-in
    /// Administrator without Admin Approval Mode) — where a standalone copy
    /// offers View only alone, because control there is administrator
    /// access and administrator access needs Tornect installed; standalone;
    /// a standard account whose policy denies elevation (or UAC off);
    /// an administrator account set to elevate without prompting — View
    /// only and the administrator answer with the Tornect confirmation, no
    /// plain Allow, because control there is administrator access in effect;
    /// installed.
    #[must_use]
    pub fn of(windows: Option<&WindowsFacts>) -> Self {
        let Some(f) = windows else {
            return Self::LINUX;
        };
        let shared = f.prompt_on_secure_desktop == Some(0);
        let row = |row, answers, sentence| Self {
            row,
            answers,
            sentence: Some(sentence),
            prompts_on_shared_screen: shared,
        };
        let uac = f.uac_on();
        if f.elevated && uac {
            return Self {
                row: HostRow::WindowsStartedElevated,
                answers: Answers::NONE,
                sentence: Some(SENTENCE_STARTED_ELEVATED),
                prompts_on_shared_screen: shared,
            };
        }
        let always_admin = f.administrator
            && (!uac || (f.builtin_administrator && !f.admin_approval_for_builtin()));
        if always_admin {
            if !f.installed {
                return row(
                    HostRow::WindowsStandalone,
                    Answers {
                        view_only: true,
                        allow: false,
                        admin: None,
                    },
                    SENTENCE_ALWAYS_ADMINISTRATOR_STANDALONE,
                );
            }
            return row(
                HostRow::WindowsAlwaysAdministrator,
                Answers {
                    view_only: true,
                    allow: false,
                    admin: Some(AdminPath::TornectConfirmation {
                        needs_helper: false,
                    }),
                },
                SENTENCE_ALWAYS_ADMINISTRATOR,
            );
        }
        let plain = Answers {
            view_only: true,
            allow: true,
            admin: None,
        };
        if !f.installed {
            return row(HostRow::WindowsStandalone, plain, SENTENCE_STANDALONE);
        }
        if !f.administrator && (!uac || f.consent_prompt_behavior_user == Some(0)) {
            return row(HostRow::WindowsPolicyDenies, plain, SENTENCE_POLICY_DENIES);
        }
        if f.administrator && f.consent_prompt_behavior_admin == Some(0) {
            return row(
                HostRow::WindowsAdminWithoutPrompt,
                Answers {
                    view_only: true,
                    allow: false,
                    admin: Some(AdminPath::TornectConfirmation { needs_helper: true }),
                },
                ADMIN_LINE_NO_PROMPT,
            );
        }
        Self {
            row: HostRow::WindowsInstalled,
            answers: Answers {
                admin: Some(AdminPath::WindowsPrompt),
                ..plain
            },
            sentence: None,
            prompts_on_shared_screen: shared,
        }
    }

    /// Whether the host may open its onion service: not when it was started
    /// elevated while UAC is on (§B.2.1).
    #[must_use]
    pub fn serves(&self) -> bool {
        !matches!(
            self.row,
            HostRow::WindowsStartedElevated
                | HostRow::LinuxRoot
                | HostRow::WindowsElevationUnreadable
        )
    }

    /// The row of a Windows host whose account could not be read in full:
    /// never a row more permissive than a full read could give (§B.2.1).
    /// `elevated` is whether this process runs elevated, when that much was
    /// read (`None`: not even that); `registry` holds the UAC values, read
    /// apart. Elevation unreadable: refuse, as a host started elevated does.
    /// Elevated with UAC on: that refusal. Otherwise: View only alone, and
    /// the sentence says why.
    #[must_use]
    pub fn unreadable(elevated: Option<bool>, registry: &WindowsFacts) -> Self {
        let shared = registry.prompt_on_secure_desktop == Some(0);
        match elevated {
            None => Self {
                row: HostRow::WindowsElevationUnreadable,
                answers: Answers::NONE,
                sentence: Some(SENTENCE_ELEVATION_UNREADABLE),
                prompts_on_shared_screen: shared,
            },
            Some(true) if registry.uac_on() => Self::of(Some(&WindowsFacts {
                elevated: true,
                ..*registry
            })),
            Some(_) => Self {
                row: HostRow::WindowsAccountUnreadable,
                answers: Answers {
                    view_only: true,
                    allow: false,
                    admin: None,
                },
                sentence: Some(SENTENCE_ACCOUNT_UNREADABLE),
                prompts_on_shared_screen: shared,
            },
        }
    }

    /// Whether the row's administrator answer is left out of
    /// [`Availability::offered`] because it needs the administrator helper
    /// this build does not have.
    #[must_use]
    pub fn missing_helper(&self) -> bool {
        self.answers.admin.is_some() && self.offered().admin.is_none()
    }

    /// The sentence under a sheet's buttons in this build: the row's own, or,
    /// where the row has none and its administrator answer is absent for lack
    /// of the helper, [`SENTENCE_NO_HELPER`] (a level the host cannot deliver
    /// is absent, and one sentence says why). The no-prompt row's own
    /// sentence is the administrator line, which describes the answer: with
    /// the answer absent it gives way to [`SENTENCE_NO_HELPER`] too.
    #[must_use]
    pub fn offered_sentence(&self) -> Option<&'static str> {
        if self.missing_helper() && self.row == HostRow::WindowsAdminWithoutPrompt {
            return Some(SENTENCE_NO_HELPER);
        }
        self.sentence
            .or_else(|| self.missing_helper().then_some(SENTENCE_NO_HELPER))
    }

    /// The line under "Allow" on this row: the Linux sentence on Linux,
    /// [`LINE_ALLOW_WINDOWS`] on Windows (the rows where control is
    /// administrator access in effect offer no plain Allow).
    #[must_use]
    pub fn allow_line(&self) -> &'static str {
        match self.row {
            HostRow::Linux | HostRow::LinuxRoot => SENTENCE_LINUX,
            _ => LINE_ALLOW_WINDOWS,
        }
    }

    /// What the sheet offers in this build: the row's answers, without an
    /// administrator answer that needs the administrator helper while this
    /// build has none ([`ADMIN_HELPER`]). A level the host cannot deliver is
    /// absent — never a greyed button.
    #[must_use]
    pub fn offered(&self) -> Answers {
        let admin = self.answers.admin.filter(|path| {
            ADMIN_HELPER
                || matches!(
                    path,
                    AdminPath::TornectConfirmation {
                        needs_helper: false
                    }
                )
        });
        Answers {
            admin,
            ..self.answers
        }
    }
}

impl Default for Availability {
    /// The Linux row: no administrator level.
    fn default() -> Self {
        Self::LINUX
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Windows account read that failed never lands on a more permissive
    /// row: elevation unreadable refuses; elevated with UAC on keeps the
    /// started-elevated refusal; anything else unreadable offers View only
    /// alone and says why.
    #[test]
    fn an_unreadable_account_never_widens_the_offer() {
        let registry = WindowsFacts::default();
        let blind = Availability::unreadable(None, &registry);
        assert!(!blind.serves());
        assert_eq!(blind.offered(), Answers::NONE);
        assert_eq!(blind.sentence, Some(SENTENCE_ELEVATION_UNREADABLE));
        let elevated = Availability::unreadable(Some(true), &registry);
        assert_eq!(elevated.row, HostRow::WindowsStartedElevated);
        assert!(!elevated.serves());
        for (elevated, lua) in [(false, None), (false, Some(0)), (true, Some(0))] {
            let registry = WindowsFacts {
                enable_lua: lua,
                prompt_on_secure_desktop: Some(0),
                ..WindowsFacts::default()
            };
            let view = Availability::unreadable(Some(elevated), &registry);
            assert!(view.serves(), "{elevated} {lua:?}");
            assert_eq!(
                view.offered(),
                Answers {
                    view_only: true,
                    allow: false,
                    admin: None,
                },
                "{elevated} {lua:?}"
            );
            assert_eq!(view.sentence, Some(SENTENCE_ACCOUNT_UNREADABLE));
            assert!(view.prompts_on_shared_screen);
        }
    }

    /// A Linux host running as root serves nothing and says why; the lines
    /// under the answers follow the row (§B.2.1), and where this build lacks
    /// the helper for the row's administrator answer, one sentence says so.
    #[test]
    fn a_root_host_refuses_and_every_row_has_its_lines() {
        let root = Availability::LINUX_ROOT;
        assert!(!root.serves());
        assert_eq!(root.offered(), Answers::NONE);
        assert_eq!(root.offered_sentence(), Some(SENTENCE_LINUX_ROOT));
        assert!(Availability::LINUX.serves());
        assert_eq!(Availability::LINUX.allow_line(), SENTENCE_LINUX);
        let installed = Availability::of(Some(&WindowsFacts {
            installed: true,
            administrator: true,
            ..WindowsFacts::default()
        }));
        assert_eq!(installed.row, HostRow::WindowsInstalled);
        assert_eq!(installed.allow_line(), LINE_ALLOW_WINDOWS);
        assert_eq!(installed.missing_helper(), !ADMIN_HELPER);
        if !ADMIN_HELPER {
            assert_eq!(installed.offered_sentence(), Some(SENTENCE_NO_HELPER));
        }
        let no_prompt = Availability::of(Some(&WindowsFacts {
            installed: true,
            administrator: true,
            consent_prompt_behavior_admin: Some(0),
            ..WindowsFacts::default()
        }));
        assert_eq!(no_prompt.row, HostRow::WindowsAdminWithoutPrompt);
        assert!(
            !no_prompt.offered().allow,
            "no plain Allow on the no-prompt row"
        );
        assert_eq!(
            no_prompt.offered_sentence(),
            Some(if ADMIN_HELPER {
                ADMIN_LINE_NO_PROMPT
            } else {
                SENTENCE_NO_HELPER
            }),
            "the row's own sentence where its answer is offered, else why it is absent"
        );
        assert_eq!(Availability::LINUX.offered_sentence(), Some(SENTENCE_LINUX));
    }

    fn facts() -> WindowsFacts {
        WindowsFacts {
            installed: true,
            ..WindowsFacts::default()
        }
    }

    #[test]
    fn elevation_codes_and_order() {
        for e in [Elevation::None, Elevation::Admin] {
            assert_eq!(Elevation::from_code(e.code()), Some(e));
        }
        for bad in 2..=u8::MAX {
            assert_eq!(Elevation::from_code(bad), None, "{bad}");
        }
        assert_eq!(Elevation::default(), Elevation::None);
        assert_eq!(
            Elevation::most_restrictive(Elevation::Admin, Elevation::None),
            Elevation::None
        );
        assert_eq!(
            Elevation::most_restrictive(Elevation::None, Elevation::Admin),
            Elevation::None
        );
        assert_eq!(
            Level::new(SessionMode::ViewOnly, Elevation::Admin),
            Level::VIEW_ONLY
        );
        assert_eq!(Level::VIEW_ONLY.elevation(), Elevation::None);
    }

    /// Every row of the §B.2.1 table, from the facts that select it.
    #[test]
    fn every_row_of_the_table() {
        let admin = WindowsFacts {
            administrator: true,
            ..facts()
        };
        type Case = (
            WindowsFacts,
            HostRow,
            [bool; 2],
            Option<AdminPath>,
            Option<&'static str>,
        );
        let cases: [Case; 12] = [
            (
                facts(),
                HostRow::WindowsInstalled,
                [true, true],
                Some(AdminPath::WindowsPrompt),
                None,
            ),
            (
                admin,
                HostRow::WindowsInstalled,
                [true, true],
                Some(AdminPath::WindowsPrompt),
                None,
            ),
            (
                WindowsFacts {
                    installed: false,
                    ..admin
                },
                HostRow::WindowsStandalone,
                [true, true],
                None,
                Some(SENTENCE_STANDALONE),
            ),
            (
                WindowsFacts {
                    enable_lua: Some(0),
                    ..admin
                },
                HostRow::WindowsAlwaysAdministrator,
                [true, false],
                Some(AdminPath::TornectConfirmation {
                    needs_helper: false,
                }),
                Some(SENTENCE_ALWAYS_ADMINISTRATOR),
            ),
            (
                WindowsFacts {
                    builtin_administrator: true,
                    ..admin
                },
                HostRow::WindowsAlwaysAdministrator,
                [true, false],
                Some(AdminPath::TornectConfirmation {
                    needs_helper: false,
                }),
                Some(SENTENCE_ALWAYS_ADMINISTRATOR),
            ),
            (
                WindowsFacts {
                    builtin_administrator: true,
                    filter_administrator_token: Some(1),
                    ..admin
                },
                HostRow::WindowsInstalled,
                [true, true],
                Some(AdminPath::WindowsPrompt),
                None,
            ),
            (
                WindowsFacts {
                    enable_lua: Some(0),
                    installed: false,
                    ..admin
                },
                HostRow::WindowsStandalone,
                [true, false],
                None,
                Some(SENTENCE_ALWAYS_ADMINISTRATOR_STANDALONE),
            ),
            (
                WindowsFacts {
                    consent_prompt_behavior_user: Some(0),
                    ..facts()
                },
                HostRow::WindowsPolicyDenies,
                [true, true],
                None,
                Some(SENTENCE_POLICY_DENIES),
            ),
            (
                WindowsFacts {
                    enable_lua: Some(0),
                    ..facts()
                },
                HostRow::WindowsPolicyDenies,
                [true, true],
                None,
                Some(SENTENCE_POLICY_DENIES),
            ),
            (
                WindowsFacts {
                    consent_prompt_behavior_admin: Some(0),
                    ..admin
                },
                HostRow::WindowsAdminWithoutPrompt,
                [true, false],
                Some(AdminPath::TornectConfirmation { needs_helper: true }),
                Some(ADMIN_LINE_NO_PROMPT),
            ),
            (
                WindowsFacts {
                    elevated: true,
                    ..admin
                },
                HostRow::WindowsStartedElevated,
                [false, false],
                None,
                Some(SENTENCE_STARTED_ELEVATED),
            ),
            (
                // UAC off: a full token is not "started elevated".
                WindowsFacts {
                    elevated: true,
                    enable_lua: Some(0),
                    ..admin
                },
                HostRow::WindowsAlwaysAdministrator,
                [true, false],
                Some(AdminPath::TornectConfirmation {
                    needs_helper: false,
                }),
                Some(SENTENCE_ALWAYS_ADMINISTRATOR),
            ),
        ];
        for (i, (f, row, [view_only, allow], admin, sentence)) in cases.into_iter().enumerate() {
            let a = Availability::of(Some(&f));
            assert_eq!(a.row, row, "case {i}");
            assert_eq!(
                a.answers,
                Answers {
                    view_only,
                    allow,
                    admin
                },
                "case {i}"
            );
            assert_eq!(a.sentence, sentence, "case {i}");
            assert_eq!(
                a.serves(),
                row != HostRow::WindowsStartedElevated,
                "case {i}"
            );
            assert!(!a.prompts_on_shared_screen, "case {i}");
        }
        let linux = Availability::of(None);
        assert_eq!(linux, Availability::LINUX);
        assert_eq!(linux.sentence, Some(SENTENCE_LINUX));
        assert!(linux.serves() && linux.answers.view_only && linux.answers.allow);
        assert_eq!(linux.answers.admin, None);
        let shared = Availability::of(Some(&WindowsFacts {
            prompt_on_secure_desktop: Some(0),
            ..facts()
        }));
        assert!(shared.prompts_on_shared_screen);
        assert_eq!(shared.row, HostRow::WindowsInstalled);
    }

    /// A level the host cannot deliver is absent: without the administrator
    /// helper only the always-administrator row offers the administrator
    /// answer; with it, the installed and the no-prompt rows offer theirs.
    #[test]
    fn only_what_this_build_can_deliver_is_offered() {
        let admin = WindowsFacts {
            administrator: true,
            ..facts()
        };
        let with_helper = |path| ADMIN_HELPER.then_some(path);
        for (f, offered_admin) in [
            (admin, with_helper(AdminPath::WindowsPrompt)),
            (
                WindowsFacts {
                    consent_prompt_behavior_admin: Some(0),
                    ..admin
                },
                with_helper(AdminPath::TornectConfirmation { needs_helper: true }),
            ),
            (
                WindowsFacts {
                    enable_lua: Some(0),
                    ..admin
                },
                Some(AdminPath::TornectConfirmation {
                    needs_helper: false,
                }),
            ),
        ] {
            let a = Availability::of(Some(&f));
            assert_eq!(a.offered().admin, offered_admin, "{:?}", a.row);
            assert_eq!(a.offered().view_only, a.answers.view_only);
            assert_eq!(a.offered().allow, a.answers.allow);
        }
        assert_eq!(Availability::LINUX.offered(), Availability::LINUX.answers);
    }

    /// The no-prompt row (`ConsentPromptBehaviorAdmin` 0, the operator's
    /// ruling of 2026-09-29) gives the always-administrator set: View only
    /// and "Allow as administrator" with the Tornect confirmation, never
    /// plain control; its answer takes the helper, since the host's own token
    /// is filtered there.
    #[test]
    fn the_no_prompt_row_is_the_always_administrator_set() {
        let row = Availability::of(Some(&WindowsFacts {
            administrator: true,
            consent_prompt_behavior_admin: Some(0),
            ..facts()
        }));
        assert_eq!(row.row, HostRow::WindowsAdminWithoutPrompt);
        assert!(row.answers.offers(Level::VIEW_ONLY));
        assert!(
            !row.answers.offers(Level::CONTROL),
            "control there is administrator access"
        );
        assert!(row.answers.offers(Level::ADMIN));
        assert_eq!(
            row.answers.admin,
            Some(AdminPath::TornectConfirmation { needs_helper: true })
        );
        assert_eq!(row.sentence, Some(ADMIN_LINE_NO_PROMPT));
        assert!(!row.offered().offers(Level::CONTROL));
        assert_eq!(row.offered().offers(Level::ADMIN), ADMIN_HELPER);
    }

    /// The clamp: every combination of a grant's level, the request and what
    /// the host delivers yields the most restrictive of the three, and
    /// view-only never carries an elevation.
    #[test]
    fn the_clamp_is_the_most_restrictive() {
        let levels = [Level::VIEW_ONLY, Level::CONTROL, Level::ADMIN];
        let modes = [SessionMode::Control, SessionMode::ViewOnly];
        let elevations = [Elevation::None, Elevation::Admin];
        for grant in levels {
            for want_mode in modes {
                for want in elevations {
                    for deliverable in elevations {
                        let got = grant.clamp(want_mode, want, deliverable);
                        let mode = SessionMode::most_restrictive(grant.mode(), want_mode);
                        assert_eq!(got.mode(), mode);
                        let elevation = if mode == SessionMode::ViewOnly {
                            Elevation::None
                        } else {
                            grant.elevation().min(want).min(deliverable)
                        };
                        assert_eq!(
                            got.elevation(),
                            elevation,
                            "{grant:?} {want_mode:?} {want:?} {deliverable:?}"
                        );
                        assert!(got.elevation() <= grant.elevation());
                        assert!(got.elevation() <= want && got.elevation() <= deliverable);
                    }
                }
            }
        }
    }

    /// An answer is its level when the row offers it, and refused otherwise:
    /// never lowered, never raised.
    #[test]
    fn an_answer_off_the_offer_is_refused() {
        let all = Answers {
            view_only: true,
            allow: true,
            admin: Some(AdminPath::WindowsPrompt),
        };
        assert!(
            all.offers(Level::VIEW_ONLY) && all.offers(Level::CONTROL) && all.offers(Level::ADMIN)
        );
        assert_eq!(all.deliverable(), Elevation::Admin);
        let linux = Availability::LINUX.offered();
        assert!(linux.offers(Level::VIEW_ONLY) && linux.offers(Level::CONTROL));
        assert!(!linux.offers(Level::ADMIN));
        assert_eq!(linux.deliverable(), Elevation::None);
        let always = Availability::of(Some(&WindowsFacts {
            administrator: true,
            enable_lua: Some(0),
            ..facts()
        }))
        .offered();
        assert!(always.offers(Level::ADMIN) && always.offers(Level::VIEW_ONLY));
        assert!(
            !always.offers(Level::CONTROL),
            "control there is administrator access"
        );
        assert!(!Answers::NONE.offers(Level::VIEW_ONLY));
    }
}
