//! The availability probe of the session levels (`docs/PLAN.md` §B.2.1;
//! decisions M1-64, M1-65): what this computer lets a host sheet offer.
//!
//! Linux has one row. On Windows the probe reads where the executable lies
//! (installed under Program Files, or standalone), five UAC values under
//! `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` and this
//! process's token (an administrator account, the built-in Administrator,
//! started elevated), and [`tornect_core::levels::Availability::of`] turns
//! them into the table's row. The reading goes through [`PolicyValues`], so
//! every row is tested here over a fake registry; the real registry and
//! token reads are NEEDS-DEVICE(windows).

use tornect_core::levels::{Availability, WindowsFacts};

/// The registry key the UAC values live under.
pub const POLICY_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";

/// The five values the probe reads (§B.2.1).
pub const POLICY_VALUES: [&str; 5] = [
    "EnableLUA",
    "FilterAdministratorToken",
    "ConsentPromptBehaviorUser",
    "ConsentPromptBehaviorAdmin",
    "PromptOnSecureDesktop",
];

/// Where the UAC values are read from: the registry, or a fake in tests.
pub trait PolicyValues {
    /// The `REG_DWORD` value `name` under [`POLICY_KEY`]; `None` when it is
    /// absent or cannot be read (Windows' default then applies).
    fn dword(&self, name: &str) -> Option<u32>;
}

/// What the probe learns from the executable's location and the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Account {
    /// The executable lies under Program Files.
    pub installed: bool,
    /// The account is an administrator (counting a filtered token).
    pub administrator: bool,
    /// The account is the built-in Administrator (RID 500).
    pub builtin_administrator: bool,
    /// This process runs elevated (`TokenElevationTypeFull`).
    pub elevated: bool,
}

/// The facts of the §B.2.1 table from `values` and `account`.
#[must_use]
pub fn windows_facts(values: &dyn PolicyValues, account: Account) -> WindowsFacts {
    WindowsFacts {
        installed: account.installed,
        enable_lua: values.dword("EnableLUA"),
        filter_administrator_token: values.dword("FilterAdministratorToken"),
        consent_prompt_behavior_user: values.dword("ConsentPromptBehaviorUser"),
        consent_prompt_behavior_admin: values.dword("ConsentPromptBehaviorAdmin"),
        prompt_on_secure_desktop: values.dword("PromptOnSecureDesktop"),
        administrator: account.administrator,
        builtin_administrator: account.builtin_administrator,
        elevated: account.elevated,
    }
}

/// This computer's row of the §B.2.1 table. On Linux (and every system but
/// Windows) the Linux row. On Windows the registry and the token; a token
/// that cannot be read counts as a standard, non-elevated, standalone
/// account — the row that offers the least.
#[must_use]
pub fn probe() -> Availability {
    #[cfg(windows)]
    {
        let account = crate::win::level_account().unwrap_or_else(|e| {
            tracing::warn!(error = %e, "reading this process's token for the session levels");
            Account::default()
        });
        Availability::of(Some(&windows_facts(&crate::win::PolicyRegistry, account)))
    }
    #[cfg(not(windows))]
    {
        Availability::of(None)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use tornect_core::levels::{
        ADMIN_LINE_NO_PROMPT, AdminPath, HostRow, SENTENCE_ALWAYS_ADMINISTRATOR,
        SENTENCE_ALWAYS_ADMINISTRATOR_STANDALONE, SENTENCE_POLICY_DENIES, SENTENCE_STANDALONE,
        SENTENCE_STARTED_ELEVATED,
    };

    use super::*;

    /// A fake registry: the values set, every other one absent.
    struct Fake(HashMap<&'static str, u32>);

    impl PolicyValues for Fake {
        fn dword(&self, name: &str) -> Option<u32> {
            assert!(POLICY_VALUES.contains(&name), "the probe read {name}");
            self.0.get(name).copied()
        }
    }

    fn fake(values: &[(&'static str, u32)]) -> Fake {
        Fake(values.iter().copied().collect())
    }

    /// The registry of a default Windows install: every value written, at
    /// Windows' defaults.
    fn defaults() -> Vec<(&'static str, u32)> {
        vec![
            ("EnableLUA", 1),
            ("FilterAdministratorToken", 0),
            ("ConsentPromptBehaviorUser", 3),
            ("ConsentPromptBehaviorAdmin", 5),
            ("PromptOnSecureDesktop", 1),
        ]
    }

    fn with(changes: &[(&'static str, u32)]) -> Fake {
        let mut values: HashMap<_, _> = defaults().into_iter().collect();
        values.extend(changes.iter().copied());
        Fake(values)
    }

    const USER: Account = Account {
        installed: true,
        administrator: false,
        builtin_administrator: false,
        elevated: false,
    };
    const ADMIN: Account = Account {
        administrator: true,
        ..USER
    };

    /// Every row of the table through the fake registry: the buttons (Deny
    /// is always first and always there), the sentence, and whether the host
    /// serves at all.
    #[test]
    fn every_row_through_a_fake_registry() {
        type Row = (
            Fake,
            Account,
            HostRow,
            bool,
            bool,
            Option<AdminPath>,
            Option<&'static str>,
        );
        let rows: Vec<Row> = vec![
            (
                with(&[]),
                USER,
                HostRow::WindowsInstalled,
                true,
                true,
                Some(AdminPath::WindowsPrompt),
                None,
            ),
            (
                with(&[]),
                ADMIN,
                HostRow::WindowsInstalled,
                true,
                true,
                Some(AdminPath::WindowsPrompt),
                None,
            ),
            // No value written at all: Windows' defaults, the same row.
            (
                fake(&[]),
                ADMIN,
                HostRow::WindowsInstalled,
                true,
                true,
                Some(AdminPath::WindowsPrompt),
                None,
            ),
            (
                with(&[]),
                Account {
                    installed: false,
                    ..ADMIN
                },
                HostRow::WindowsStandalone,
                true,
                true,
                None,
                Some(SENTENCE_STANDALONE),
            ),
            (
                with(&[("EnableLUA", 0)]),
                ADMIN,
                HostRow::WindowsAlwaysAdministrator,
                true,
                false,
                Some(AdminPath::TornectConfirmation {
                    needs_helper: false,
                }),
                Some(SENTENCE_ALWAYS_ADMINISTRATOR),
            ),
            (
                with(&[("FilterAdministratorToken", 0)]),
                Account {
                    builtin_administrator: true,
                    ..ADMIN
                },
                HostRow::WindowsAlwaysAdministrator,
                true,
                false,
                Some(AdminPath::TornectConfirmation {
                    needs_helper: false,
                }),
                Some(SENTENCE_ALWAYS_ADMINISTRATOR),
            ),
            (
                with(&[("EnableLUA", 0)]),
                Account {
                    installed: false,
                    ..ADMIN
                },
                HostRow::WindowsStandalone,
                true,
                false,
                None,
                Some(SENTENCE_ALWAYS_ADMINISTRATOR_STANDALONE),
            ),
            (
                with(&[("ConsentPromptBehaviorUser", 0)]),
                USER,
                HostRow::WindowsPolicyDenies,
                true,
                true,
                None,
                Some(SENTENCE_POLICY_DENIES),
            ),
            (
                with(&[("ConsentPromptBehaviorAdmin", 0)]),
                ADMIN,
                HostRow::WindowsAdminWithoutPrompt,
                true,
                true,
                Some(AdminPath::TornectConfirmation { needs_helper: true }),
                Some(ADMIN_LINE_NO_PROMPT),
            ),
            (
                with(&[]),
                Account {
                    elevated: true,
                    ..ADMIN
                },
                HostRow::WindowsStartedElevated,
                false,
                false,
                None,
                Some(SENTENCE_STARTED_ELEVATED),
            ),
        ];
        for (i, (values, account, row, view_only, allow, admin, sentence)) in
            rows.into_iter().enumerate()
        {
            let a = Availability::of(Some(&windows_facts(&values, account)));
            assert_eq!(a.row, row, "row {i}");
            assert_eq!(
                (a.answers.view_only, a.answers.allow, a.answers.admin),
                (view_only, allow, admin),
                "row {i}"
            );
            assert_eq!(a.sentence, sentence, "row {i}");
            assert_eq!(
                a.serves(),
                row != HostRow::WindowsStartedElevated,
                "row {i}"
            );
        }
        // `PromptOnSecureDesktop` 0 adds its sentence at every level.
        let shared = Availability::of(Some(&windows_facts(
            &with(&[("PromptOnSecureDesktop", 0)]),
            ADMIN,
        )));
        assert!(shared.prompts_on_shared_screen);
        let secure = Availability::of(Some(&windows_facts(&with(&[]), ADMIN)));
        assert!(!secure.prompts_on_shared_screen);
    }

    /// Linux: the three-answer row with its sentence, whatever the account.
    #[cfg(not(windows))]
    #[test]
    fn linux_is_always_the_three_answer_row() {
        use tornect_core::levels::SENTENCE_LINUX;

        let a = probe();
        assert_eq!(a.row, HostRow::Linux);
        assert!(a.serves());
        assert_eq!(a.sentence, Some(SENTENCE_LINUX));
        assert!(a.answers.view_only && a.answers.allow && a.answers.admin.is_none());
        assert_eq!(a.offered(), a.answers);
    }
}
