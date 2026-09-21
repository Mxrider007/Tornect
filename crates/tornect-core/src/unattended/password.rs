//! The grant-password policy of `docs/PLAN.md` §B.8.7.2, enforced on the client / CLI
//! side (the host never sees the password): NFC, never trimmed (warned), whitespace
//! and hyphen runs between words collapsed to one space, 12–128 characters, `zxcvbn`
//! score ≥ 3 with the caller's `user_inputs` — ≥ 4 on a file-keystore host.

use core::fmt;

use unicode_normalization::UnicodeNormalization as _;
use zeroize::Zeroizing;

/// Minimum length in characters.
pub const MIN_CHARS: usize = 12;
/// Maximum length in characters.
pub const MAX_CHARS: usize = 128;
/// Required `zxcvbn` score with an OS keychain.
pub const MIN_SCORE: u8 = 3;
/// Required `zxcvbn` score on a file-keystore host (§B.8.7.2, T3b).
pub const MIN_SCORE_FILE_KEYSTORE: u8 = 4;
/// `user_inputs` entry every check adds (§B.8.7.2).
pub const ALWAYS_USER_INPUT: &str = "tornect";

/// Why a password was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    /// Fewer than 12 characters after normalization.
    #[error("password has {chars} characters; at least {MIN_CHARS} are required")]
    TooShort {
        /// Character count.
        chars: usize,
    },
    /// More than 128 characters after normalization.
    #[error("password has {chars} characters; at most {MAX_CHARS} are allowed")]
    TooLong {
        /// Character count.
        chars: usize,
    },
    /// `zxcvbn` score below the requirement.
    #[error("password is too weak (score {score}, required {required}){}", feedback.as_deref().map(|f| format!(": {f}")).unwrap_or_default())]
    TooWeak {
        /// Measured score (0–4).
        score: u8,
        /// Required score.
        required: u8,
        /// `zxcvbn` warning text, if any.
        feedback: Option<String>,
    },
    /// The EFF long word list is not available offline in any pinned crate (decision M1-19).
    #[error("passphrase generation unavailable: no offline word list is compiled in")]
    WordListUnavailable,
}

/// Non-fatal notes surfaced next to the meter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyWarning {
    /// The password starts with whitespace (kept, never trimmed).
    LeadingWhitespace,
    /// The password ends with whitespace (kept, never trimmed).
    TrailingWhitespace,
}

/// A password that passed the policy, in its normalized form.
pub struct CheckedPassword {
    /// The normalized password (what registration and login must use on both sides).
    pub password: Zeroizing<String>,
    /// Non-fatal notes.
    pub warnings: Vec<PolicyWarning>,
    /// The `zxcvbn` score (0–4).
    pub score: u8,
}

impl fmt::Debug for CheckedPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CheckedPassword")
            .field("password", &"<redacted>")
            .field("chars", &self.password.chars().count())
            .field("warnings", &self.warnings)
            .field("score", &self.score)
            .finish()
    }
}

/// The required score for the host's keystore.
#[must_use]
pub fn required_score(file_keystore: bool) -> u8 {
    if file_keystore {
        MIN_SCORE_FILE_KEYSTORE
    } else {
        MIN_SCORE
    }
}

fn is_separator(c: char) -> bool {
    c.is_whitespace() || c == '-'
}

/// NFC-normalize and collapse whitespace/hyphen runs *between* words to one space;
/// leading and trailing runs are kept untouched (never trimmed).
#[must_use]
pub fn normalize(pw: &str) -> Zeroizing<String> {
    // Every intermediate is zeroized on drop (§B.8.7.2, A14), and each is sized
    // before it is filled: a buffer that grows leaves its outgrown copies in freed
    // memory, unwiped. NFC grows a string by at most 3× (Unicode's stability bound).
    let mut nfc = Zeroizing::new(String::with_capacity(pw.len().saturating_mul(3)));
    nfc.extend(pw.nfc());
    let mut chars: Zeroizing<Vec<char>> = Zeroizing::new(Vec::with_capacity(nfc.len()));
    chars.extend(nfc.chars());
    let first_word = chars.iter().position(|c| !is_separator(*c));
    let last_word = chars.iter().rposition(|c| !is_separator(*c));
    let mut out = Zeroizing::new(String::with_capacity(nfc.len()));
    match (first_word, last_word) {
        (Some(first), Some(last)) => {
            out.extend(chars[..first].iter());
            let mut in_run = false;
            for &c in &chars[first..=last] {
                if is_separator(c) {
                    if !in_run {
                        out.push(' ');
                        in_run = true;
                    }
                } else {
                    out.push(c);
                    in_run = false;
                }
            }
            out.extend(chars[last + 1..].iter());
        }
        _ => out.push_str(&nfc),
    }
    out
}

/// Apply the policy; `user_inputs` are the host name, device labels, onion address and
/// OS user name (`"tornect"` is always added).
pub fn check(
    pw: &str,
    user_inputs: &[&str],
    file_keystore: bool,
) -> Result<CheckedPassword, PolicyError> {
    let password = normalize(pw);
    let chars = password.chars().count();
    if chars < MIN_CHARS {
        return Err(PolicyError::TooShort { chars });
    }
    if chars > MAX_CHARS {
        return Err(PolicyError::TooLong { chars });
    }
    // user inputs get the same normalization so a hyphenated host name still matches
    let normalized_inputs: Vec<Zeroizing<String>> =
        user_inputs.iter().map(|s| normalize(s)).collect();
    let mut inputs: Vec<&str> = user_inputs.to_vec();
    inputs.extend(normalized_inputs.iter().map(|s| s.as_str()));
    inputs.push(ALWAYS_USER_INPUT);
    let entropy = zxcvbn::zxcvbn(&password, &inputs);
    let score = u8::from(entropy.score());
    let required = required_score(file_keystore);
    if score < required {
        return Err(PolicyError::TooWeak {
            score,
            required,
            feedback: entropy
                .feedback()
                .and_then(|f| f.warning())
                .map(|w| w.to_string()),
        });
    }
    let mut warnings = Vec::new();
    if password.starts_with(char::is_whitespace) {
        warnings.push(PolicyWarning::LeadingWhitespace);
    }
    if password.ends_with(char::is_whitespace) {
        warnings.push(PolicyWarning::TrailingWhitespace);
    }
    Ok(CheckedPassword {
        password,
        warnings,
        score,
    })
}

/// Five EFF-long-list words (≈ 64.6 bits). No pinned crate ships the 7776-word list
/// offline and it is not vendored from memory (decision M1-19), so this returns
/// [`PolicyError::WordListUnavailable`] until a verified list is added; the UI offers
/// "use my own" with the live meter meanwhile.
pub fn generate_passphrase() -> Result<Zeroizing<String>, PolicyError> {
    Err(PolicyError::WordListUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u3_policy_nfc_and_whitespace_rules() {
        // decomposed é → composed é
        let n = normalize("cafe\u{301} latte");
        assert_eq!(n.as_str(), "caf\u{e9} latte");
        assert_eq!(
            normalize("correct   horse-battery--staple").as_str(),
            "correct horse battery staple"
        );
        assert_eq!(
            normalize("  lead and trail  ").as_str(),
            "  lead and trail  ",
            "never trimmed"
        );
        assert_eq!(normalize("---").as_str(), "---");
        let c = check("  quiet-verdant--otter  lantern ", &[], false).unwrap();
        assert_eq!(c.password.as_str(), "  quiet verdant otter lantern ");
        assert_eq!(
            c.warnings,
            vec![
                PolicyWarning::LeadingWhitespace,
                PolicyWarning::TrailingWhitespace
            ]
        );
        assert!(!format!("{c:?}").contains("otter"));
        // A14: neither the Debug form nor any error string carries the password.
        let secret = "correct horse battery staple x9";
        for (inputs, file) in [(&[][..], false), (&[secret][..], true)] {
            match check(secret, inputs, file) {
                Ok(c) => assert!(!format!("{c:?}").contains("horse")),
                Err(e) => {
                    assert!(!e.to_string().contains("horse"), "{e}");
                    assert!(!format!("{e:?}").contains("horse"), "{e:?}");
                }
            }
        }
    }

    #[test]
    fn u3_policy_length_bounds() {
        assert_eq!(
            check("short-pw", &[], false).unwrap_err(),
            PolicyError::TooShort { chars: 8 }
        );
        // separators collapse before the count: "ab--cd  ef" is 8 characters
        assert_eq!(
            check("ab--cd  ef", &[], false).unwrap_err(),
            PolicyError::TooShort { chars: 8 }
        );
        let long = "x7!Qz".repeat(30);
        assert_eq!(
            check(&long, &[], false).unwrap_err(),
            PolicyError::TooLong { chars: 150 }
        );
        assert_eq!(
            check("", &[], false).unwrap_err(),
            PolicyError::TooShort { chars: 0 }
        );
    }

    #[test]
    fn u3_policy_score_thresholds_and_file_keystore() {
        assert!(matches!(
            check("password1234", &[], false),
            Err(PolicyError::TooWeak { required: 3, .. })
        ));
        // the host name is a user input and counts against the password
        assert!(matches!(
            check("mx-vm-tornect-host-2026", &["mx-vm-tornect-host"], false),
            Err(PolicyError::TooWeak { .. })
        ));
        let strong = "quiet verdant otter lantern zephyr";
        let c = check(strong, &["mx-vm"], false).unwrap();
        assert!(c.score >= 3);
        let c4 = check(strong, &["mx-vm"], true).unwrap();
        assert_eq!(c4.score, 4);
        // A score-3 password is accepted with a keychain but refused on a file
        // keystore — the one behaviour the §B.8.7.2 file-keystore clause adds.
        // Search a fixed list rather than hard-coding one string: a zxcvbn bump
        // that moves a band boundary must fail here loudly, not silently drop
        // this coverage (the previous `if let ... && c.score == 3` guard was
        // dead, because "Tr0ub4dor&3x!" scores 4).
        let mid = ["amber9-thicket", "quill-8-marrow", "dusk7-pebble"]
            .into_iter()
            .find(|pw| matches!(check(pw, &[], false), Ok(c) if c.score == 3))
            .expect(
                "no candidate scores 3 under this zxcvbn version: the \
                 file-keystore escalation of §B.8.7.2 would go untested \
                 — add a score-3 candidate to this list",
            );
        assert!(matches!(
            check(mid, &[], true),
            Err(PolicyError::TooWeak {
                score: 3,
                required: 4,
                ..
            })
        ));
        assert_eq!(required_score(true), 4);
        assert_eq!(required_score(false), 3);
    }

    #[test]
    fn u3_generate_passphrase_is_unavailable_offline() {
        assert_eq!(
            generate_passphrase().unwrap_err(),
            PolicyError::WordListUnavailable
        );
    }
}
