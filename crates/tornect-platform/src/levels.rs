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

use tornect_core::levels::{AccountFacts, Availability, FactsSource, HelperPresence, WindowsFacts};

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

/// An account read that failed: whether this process runs elevated, when
/// that much was read, and why the rest could not be.
#[derive(Debug)]
pub struct Unreadable {
    /// Whether this process runs elevated; `None` when not even that was read.
    pub elevated: Option<bool>,
    /// What failed.
    pub error: std::io::Error,
}

/// The row of a Windows host from what was read of its account and the
/// UAC `values`. A failed read never falls back to a more permissive row
/// ([`Availability::unreadable`]): elevation unreadable refuses, elevated
/// with UAC on keeps the started-elevated refusal, and anything else
/// unreadable offers View only alone.
#[must_use]
pub fn windows_row(read: Result<Account, Unreadable>, values: &dyn PolicyValues) -> Availability {
    match read {
        Ok(account) => Availability::of(Some(&windows_facts(values, account))),
        Err(Unreadable { elevated, error }) => {
            tracing::warn!(error = %error, "reading this process's token for the session levels");
            Availability::unreadable(elevated, &windows_facts(values, Account::default()))
        }
    }
}

/// The account's facts from what was read (decision M1-67, A21 (h)): the token's
/// account and the UAC values, or [`AccountFacts::Unreadable`] when the token or any
/// value other than an absent one could not be read. Never the facts [`windows_row`]
/// builds for its unreadable row, whose `administrator` is false.
#[must_use]
pub fn facts_of(
    read: Result<Account, Unreadable>,
    policy_unreadable: Option<std::io::Error>,
    values: &dyn PolicyValues,
) -> AccountFacts {
    match (read, policy_unreadable) {
        (Ok(account), None) => AccountFacts::Windows(windows_facts(values, account)),
        (Err(Unreadable { error, .. }), _) | (Ok(_), Some(error)) => {
            tracing::warn!(error = %error, "reading this account's facts for an answer");
            AccountFacts::Unreadable
        }
    }
}

/// This computer's account facts now (decision M1-67): read afresh at each answer, never
/// cached from start. [`AccountFacts::Linux`] on every system but Windows.
#[must_use]
pub fn account_facts() -> AccountFacts {
    #[cfg(windows)]
    {
        facts_of(
            crate::win::level_account(),
            crate::win::policy_unreadable(),
            &crate::win::PolicyRegistry,
        )
    }
    #[cfg(not(windows))]
    {
        AccountFacts::Linux
    }
}

/// The facts and the helper task of this computer, read at each answer (decision
/// M1-67): what a host's unattended gate decides clause (ii) and F-12 from.
#[derive(Debug, Default, Clone, Copy)]
pub struct LiveFacts;

impl FactsSource for LiveFacts {
    fn account(&self) -> AccountFacts {
        account_facts()
    }

    fn helper_task(&self) -> HelperPresence {
        crate::helper_task::presence_now()
    }
}

/// This computer's row of the §B.2.1 table. On Linux (and every system but
/// Windows) the Linux row. On Windows the registry and the token
/// ([`windows_row`]).
#[must_use]
pub fn probe() -> Availability {
    #[cfg(windows)]
    {
        // A UAC value that could not be read (other than absent) is an
        // unreadable account: never the defaults' more permissive row.
        let read = match (crate::win::level_account(), crate::win::policy_unreadable()) {
            (Ok(account), Some(error)) => Err(Unreadable {
                elevated: Some(account.elevated),
                error,
            }),
            (read, _) => read,
        };
        windows_row(read, &crate::win::PolicyRegistry)
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
                false,
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

    /// DA-16 (RP-3) through the fake registry: a standalone copy on an
    /// administrator account set to elevate without prompting
    /// (`ConsentPromptBehaviorAdmin` 0, alone or among Windows' defaults)
    /// offers View only alone with its sentence; a standard account with the
    /// same value keeps plain Allow and the standalone sentence.
    #[test]
    fn the_standalone_no_prompt_row_through_a_fake_registry() {
        use tornect_core::levels::{Answers, SENTENCE_ADMIN_WITHOUT_PROMPT_STANDALONE};

        let standalone = |account: Account| Account {
            installed: false,
            ..account
        };
        for values in [
            with(&[("ConsentPromptBehaviorAdmin", 0)]),
            fake(&[("ConsentPromptBehaviorAdmin", 0)]),
        ] {
            let a = Availability::of(Some(&windows_facts(&values, standalone(ADMIN))));
            assert!(windows_facts(&values, standalone(ADMIN)).control_is_administrator());
            assert_eq!(a.row, HostRow::WindowsStandalone);
            assert_eq!(
                a.offered(),
                Answers {
                    view_only: true,
                    allow: false,
                    admin: None,
                }
            );
            assert_eq!(a.answers, a.offered());
            assert_eq!(a.sentence, Some(SENTENCE_ADMIN_WITHOUT_PROMPT_STANDALONE));
            assert_eq!(
                a.offered_sentence(),
                Some(SENTENCE_ADMIN_WITHOUT_PROMPT_STANDALONE)
            );
            assert!(a.serves());

            let user = Availability::of(Some(&windows_facts(&values, standalone(USER))));
            assert_eq!(user.row, HostRow::WindowsStandalone);
            assert!(user.offered().allow && user.offered().view_only);
            assert_eq!(user.sentence, Some(SENTENCE_STANDALONE));
        }
    }

    /// An account read that failed lands on a row no more permissive than a
    /// full read: elevation unreadable refuses; elevated with UAC on keeps
    /// the started-elevated refusal; the rest unreadable offers View only.
    #[test]
    fn a_failed_account_read_offers_the_least() {
        use tornect_core::levels::{
            Answers, SENTENCE_ACCOUNT_UNREADABLE, SENTENCE_ELEVATION_UNREADABLE,
        };
        let failed = |elevated| {
            Err(Unreadable {
                elevated,
                error: std::io::Error::other("access denied"),
            })
        };
        let values = fake(&defaults());
        let blind = windows_row(failed(None), &values);
        assert!(!blind.serves());
        assert_eq!(blind.sentence, Some(SENTENCE_ELEVATION_UNREADABLE));
        let elevated = windows_row(failed(Some(true)), &values);
        assert_eq!(elevated.row, HostRow::WindowsStartedElevated);
        assert!(!elevated.serves());
        let rest = windows_row(failed(Some(false)), &values);
        assert!(rest.serves());
        assert_eq!(
            rest.offered(),
            Answers {
                view_only: true,
                allow: false,
                admin: None,
            }
        );
        assert_eq!(rest.sentence, Some(SENTENCE_ACCOUNT_UNREADABLE));
        // UAC off on an account whose rights could not be read: View only
        // too, never control (which could be administrator access there).
        let uac_off = fake(&[("EnableLUA", 0)]);
        let off = windows_row(failed(Some(false)), &uac_off);
        assert!(!off.answers.allow && off.answers.view_only);
        // A full read still gives its row.
        let ok = windows_row(
            Ok(Account {
                installed: true,
                administrator: true,
                ..Account::default()
            }),
            &values,
        );
        assert_eq!(ok.row, HostRow::WindowsInstalled);
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

    /// Decision M1-67 (A21 (h)): a token or a UAC value that cannot be read gives
    /// "unreadable", never the facts the probe builds for its unreadable row (which say
    /// "not an administrator", so control would not count as administrator access); what
    /// was read gives the facts.
    #[test]
    fn unreadable_is_never_fed_as_default_facts() {
        let values = fake(&[]);
        let failed = || std::io::Error::other("access denied");
        let account = Account {
            administrator: true,
            ..Account::default()
        };
        for read in [
            Err(Unreadable {
                elevated: Some(false),
                error: failed(),
            }),
            Err(Unreadable {
                elevated: None,
                error: failed(),
            }),
        ] {
            let facts = facts_of(read, None, &values);
            assert_eq!(facts, AccountFacts::Unreadable);
            assert!(facts.control_is_administrator());
        }
        assert_eq!(
            facts_of(Ok(account), Some(failed()), &values),
            AccountFacts::Unreadable
        );
        // The probe's default facts would have said the opposite.
        assert!(!windows_facts(&values, Account::default()).control_is_administrator());
        let read = facts_of(Ok(account), None, &values);
        assert_eq!(read, AccountFacts::Windows(windows_facts(&values, account)));
        assert!(!read.control_is_administrator());
    }

    /// Decision M1-67: on Linux the read gives no facts and is never "unreadable"; the
    /// helper task is never there.
    #[cfg(not(windows))]
    #[test]
    fn linux_reads_no_facts_and_is_never_unreadable() {
        assert_eq!(account_facts(), AccountFacts::Linux);
        assert_eq!(LiveFacts.account(), AccountFacts::Linux);
        assert_eq!(LiveFacts.helper_task(), HelperPresence::Absent);
        assert!(!LiveFacts.account().control_is_administrator());
    }
}
