//! A field that takes a Tornect ID (design `invite` §2.2, §2.3, §3): Home's
//! connect field and the address book's Add a computer read what was typed
//! or pasted the same way, through `invite::find_id` (the ID in any written
//! form, a `tornect:` link, or a whole invitation), refuse this computer's
//! own ID, and say what is wrong with the same words. Nothing here acts: a
//! field only ever yields an ID for its own button.

use egui::{RichText, Ui};
use tornect_core::TornectId;
use tornect_core::invite::{self, Found, IdProblem};

use super::super::theme::{self, Face, Tokens};

/// What an ID field says of this computer's own ID (B26): it would ask this
/// computer for a session with itself, or save it as a computer to reach.
pub(super) const OWN_ID: &str = "That is this computer's own ID.";

/// Why an ID field holds no ID it can use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Problem {
    /// What `invite::find_id` refused, [`IdProblem::Empty`] included (the
    /// field draws no line for it).
    Id(IdProblem),
    /// This computer's own ID.
    Own,
}

/// The ID in `text`, unless it is none or this computer's own (`own`).
pub(super) fn check(text: &str, own: Option<TornectId>) -> Result<Found, Problem> {
    let found = invite::find_id(text).map_err(Problem::Id)?;
    if own == Some(found.id) {
        return Err(Problem::Own);
    }
    Ok(found)
}

/// What the field says of `problem`: the command line's words with a final
/// full stop, or [`OWN_ID`]. None of them echoes the field's text, except
/// one printable ASCII character of [`IdProblem::NotAlphabet`].
pub(super) fn message(problem: &Problem) -> String {
    match problem {
        Problem::Id(problem) => format!("{problem}."),
        Problem::Own => OWN_ID.to_owned(),
    }
}

/// The line under the field that says what is wrong, in the danger colour;
/// nothing for an empty field.
pub(super) fn problem_line(ui: &mut Ui, t: &Tokens, problem: &Problem) {
    if *problem == Problem::Id(IdProblem::Empty) {
        return;
    }
    ui.add(
        egui::Label::new(
            RichText::new(message(problem))
                .font(theme::font(ui.ctx(), Face::Regular, 12.0))
                .color(t.danger_text),
        )
        .wrap(),
    );
}

/// Rewrite `text` to the ID's groups when it just `changed` and the ID came
/// out of a link or a longer text, or invisible characters were removed
/// (`Found::rewrite`): the field then shows exactly what Connect or Save
/// takes. A cleanly typed ID is left as it is, so the cursor never jumps
/// while typing. `true` when `text` was rewritten (the caller checks it
/// again).
pub(super) fn normalize(
    text: &mut String,
    checked: &Result<Found, Problem>,
    changed: bool,
) -> bool {
    match checked {
        Ok(found) if changed && found.rewrite() => {
            *text = found.id.display_groups();
            true
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use tornect_core::invite::{self, Source};

    use super::*;

    fn key(seed: u8) -> TornectId {
        TornectId::from_public_key(
            &ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key(),
        )
    }

    /// The right shape and checksum, but 32 bytes that decode to no curve
    /// point.
    fn not_a_key() -> TornectId {
        (0..=u8::MAX)
            .map(|i| TornectId::from_bytes([i; 32]))
            .find(|id| id.verifying_key().is_err())
            .expect("some repeated byte is no curve point")
    }

    /// The field's reading is `find_id`'s, with this computer's own ID
    /// refused in every written form, a link and an invitation included.
    #[test]
    fn check_reads_every_form_and_refuses_the_own_id() {
        let (id, own) = (key(7), key(6));
        for text in [
            id.to_string(),
            id.onion_address(),
            id.display_groups(),
            invite::link(&id),
            invite::invitation(&id),
        ] {
            assert_eq!(check(&text, Some(own)).map(|f| f.id), Ok(id), "{text}");
            assert_eq!(check(&text, None).map(|f| f.id), Ok(id), "{text}");
        }
        for text in [
            own.to_string(),
            own.display_groups(),
            invite::link(&own),
            invite::invitation(&own),
        ] {
            assert_eq!(check(&text, Some(own)), Err(Problem::Own), "{text}");
        }
        assert_eq!(check("  ", Some(own)), Err(Problem::Id(IdProblem::Empty)));
        assert_eq!(
            check(&not_a_key().display_groups(), Some(own)),
            Err(Problem::Id(IdProblem::NotAKey))
        );
    }

    /// The window's words are the command line's with a full stop; the two
    /// texts the address book had are kept word for word.
    #[test]
    fn messages_are_the_shared_words_with_a_full_stop() {
        assert_eq!(
            message(&Problem::Id(IdProblem::NotAKey)),
            "That ID has the right shape but is no computer's key: check for a typo."
        );
        assert_eq!(message(&Problem::Own), "That is this computer's own ID.");
        assert_eq!(
            message(&Problem::Id(IdProblem::Short { found: 7 })),
            "7 of 56 characters."
        );
        assert_eq!(
            message(&Problem::Id(IdProblem::NotAlphabet(Some('\u{202E}')))),
            "IDs hold only the letters a–z and the digits 2–7."
        );
    }

    /// Only a change that came from a link, a longer text or stripped
    /// invisible characters rewrites the field; a cleanly typed ID, a
    /// refusal and a pass without a change never do.
    #[test]
    fn normalize_rewrites_only_what_was_not_typed_cleanly() {
        let id = key(7);
        let groups = id.display_groups();
        let spaced: String = id
            .to_string()
            .chars()
            .flat_map(|c| [c, '\u{200B}'])
            .collect();
        for (text, rewritten) in [
            (invite::invitation(&id), true),
            (invite::link(&id), true),
            (format!("my id is {id}"), true),
            (spaced, true),
            (id.to_string(), false),
            (id.onion_address(), false),
            (groups.clone(), false),
            ("abc".to_owned(), false),
        ] {
            let checked = check(&text, None);
            let mut field = text.clone();
            assert!(!normalize(&mut field, &checked, false), "{text}");
            assert_eq!(field, text);
            assert_eq!(normalize(&mut field, &checked, true), rewritten, "{text}");
            if rewritten {
                assert_eq!(field, groups);
                let again = check(&field, None).expect("the groups are an ID");
                assert_eq!((again.id, again.source), (id, Source::Typed));
                assert!(!again.rewrite());
            } else {
                assert_eq!(field, text);
            }
        }
    }
}
