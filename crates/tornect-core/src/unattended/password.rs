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
    /// The compiled-in word list does not read as EFF's 7776 words (never with the pinned
    /// file: `the_eff_list_matches_its_checksum` checks it).
    #[error("passphrase generation unavailable: the compiled-in word list is not EFF's long list")]
    WordListUnavailable,
    /// The operating system gave no random bytes.
    #[error("passphrase generation failed: no random bytes from the operating system ({0})")]
    RandomUnavailable(String),
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

/// EFF's long word list as EFF publishes it (`data/eff_large_wordlist.txt`, an unchanged
/// copy; `packaging/licenses/SOURCES.md`): 7776 lines of five dice digits, a tab and a
/// word.
const EFF_LONG_LIST: &str = include_str!("../../data/eff_large_wordlist.txt");

/// SHA-256 of the embedded EFF long word list: the published file's bytes, unchanged
/// (`packaging/licenses/SOURCES.md`; decision M1-19's later track).
pub const EFF_LONG_LIST_SHA256: &str =
    "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e";

/// Words in EFF's long list: one per throw of five dice (6⁵).
pub const EFF_LONG_LIST_WORDS: usize = 7776;

/// Words in a generated passphrase (§B.8.7.1 ④: ≈ 64.6 bits).
pub const PASSPHRASE_WORDS: usize = 5;

/// The list's words in list order, the dice column skipped; `None` unless every line is
/// "dice, tab, word" and there are exactly [`EFF_LONG_LIST_WORDS`] (never with the
/// pinned file).
fn eff_long_list() -> Option<&'static [&'static str]> {
    static WORDS: std::sync::OnceLock<Option<Vec<&'static str>>> = std::sync::OnceLock::new();
    WORDS
        .get_or_init(|| {
            let words: Option<Vec<&'static str>> = EFF_LONG_LIST
                .lines()
                .map(|line| line.split_once('\t').map(|(_dice, word)| word))
                .collect();
            words.filter(|w| w.len() == EFF_LONG_LIST_WORDS)
        })
        .as_deref()
}

/// A number below `n` (`n > 0`), every value equally likely: a 32-bit draw at or above
/// the largest multiple of `n` is drawn again, so the remainder favours no value.
fn uniform_below(n: u32) -> Result<u32, PolicyError> {
    let zone = u32::MAX - u32::MAX % n;
    loop {
        let mut bytes = Zeroizing::new([0u8; 4]);
        getrandom::fill(bytes.as_mut_slice())
            .map_err(|e| PolicyError::RandomUnavailable(e.to_string()))?;
        let draw = u32::from_le_bytes(*bytes);
        if draw < zone {
            return Ok(draw % n);
        }
    }
}

/// Five words of EFF's long list (≈ 64.6 bits, §B.8.7.1 ④), each drawn uniformly and
/// independently with the operating system's random source, joined by single spaces.
/// The words keep the list's spelling: four of them hold a hyphen, which [`normalize`]
/// reads as a space on both sides (§B.8.7.2). Only this generator's passwords may
/// later be registered as `generated` (decision M1-67).
pub fn generate_passphrase() -> Result<Zeroizing<String>, PolicyError> {
    let words = eff_long_list().ok_or(PolicyError::WordListUnavailable)?;
    let n = u32::try_from(words.len()).map_err(|_| PolicyError::WordListUnavailable)?;
    // Sized before it is filled (5 words of at most 9 letters and 4 spaces): a string
    // that grows leaves its outgrown copies in freed memory, unwiped.
    let mut out = Zeroizing::new(String::with_capacity(PASSPHRASE_WORDS * 10));
    for i in 0..PASSPHRASE_WORDS {
        let index = uniform_below(n)?;
        if i > 0 {
            out.push(' ');
        }
        out.push_str(words[index as usize]);
    }
    Ok(out)
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
            check(
                "build-vm-tornect-host-2026",
                &["build-vm-tornect-host"],
                false
            ),
            Err(PolicyError::TooWeak { .. })
        ));
        let strong = "quiet verdant otter lantern zephyr";
        let c = check(strong, &["build-vm"], false).unwrap();
        assert!(c.score >= 3);
        let c4 = check(strong, &["build-vm"], true).unwrap();
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

    /// The five dice of line `i` (0-based), as EFF numbers its lines: 11111 to 66666.
    fn dice_of(i: usize) -> String {
        let mut digits = [b'1'; 5];
        let mut rest = i;
        for d in digits.iter_mut().rev() {
            *d = b'1' + u8::try_from(rest % 6).unwrap();
            rest /= 6;
        }
        String::from_utf8(digits.to_vec()).unwrap()
    }

    #[test]
    fn the_eff_list_matches_its_checksum() {
        use sha2::{Digest as _, Sha256};
        // The pinned bytes: EFF's published file, unchanged (packaging/licenses/SOURCES.md),
        // as committed with LF line ends (a Windows checkout may turn them into CRLF, and
        // the Windows CI job runs these tests).
        let committed = EFF_LONG_LIST.replace("\r\n", "\n");
        assert_eq!(
            hex::encode(Sha256::digest(committed.as_bytes())),
            EFF_LONG_LIST_SHA256
        );
        assert_eq!(committed.len(), 108_800);
        assert!(committed.ends_with('\n') && !committed.contains('\r'));
        // Its shape: 7776 lines "dice, tab, word", the dice 11111 to 66666 in order.
        let lines: Vec<&str> = committed.lines().collect();
        assert_eq!(lines.len(), EFF_LONG_LIST_WORDS);
        for (i, line) in lines.iter().enumerate() {
            let (dice, word) = line.split_once('\t').unwrap();
            assert_eq!(dice, dice_of(i), "line {}", i + 1);
            assert!(
                (3..=9).contains(&word.len())
                    && word.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'),
                "line {}: {line}",
                i + 1
            );
        }
        // The parser skips the dice: the words in list order, all different.
        let words = eff_long_list().unwrap();
        assert_eq!(words.len(), EFF_LONG_LIST_WORDS);
        assert_eq!(
            (words[0], words[EFF_LONG_LIST_WORDS - 1]),
            ("abacus", "zoom")
        );
        let mut unique = words.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), EFF_LONG_LIST_WORDS, "every word once");
    }

    #[test]
    fn a_passphrase_is_five_list_words() {
        let words = eff_long_list().unwrap();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let phrase = generate_passphrase().unwrap();
            let drawn: Vec<&str> = phrase.split(' ').collect();
            assert_eq!(drawn.len(), PASSPHRASE_WORDS, "{}", phrase.as_str());
            assert!(
                drawn.iter().all(|w| words.contains(w)),
                "{}",
                phrase.as_str()
            );
            // between 19 and 49 characters: always inside the policy's 12 to 128
            let chars = normalize(&phrase).chars().count();
            assert!((MIN_CHARS..=MAX_CHARS).contains(&chars));
            seen.insert(phrase.to_string());
        }
        // 200 draws from 7776⁵ phrases: a repeat would mean a broken random source.
        assert_eq!(seen.len(), 200);
        // The draw below n keeps a zone that is a multiple of n and leaves out fewer
        // than n values, so no remainder is favoured; every value comes up.
        let zone = u32::MAX - u32::MAX % 7776;
        assert_eq!(zone % 7776, 0);
        assert!(u32::MAX - zone < 7776);
        let mut hit = [false; 6];
        for _ in 0..600 {
            hit[uniform_below(6).unwrap() as usize] = true;
        }
        assert!(hit.iter().all(|h| *h), "{hit:?}");
    }
}
