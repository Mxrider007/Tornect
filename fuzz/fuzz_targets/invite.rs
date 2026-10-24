//! The invitation parsers of `tornect_core::invite` (design `invite` §4.1–§4.2) and
//! `TornectId::from_str`, fed arbitrary text: every reading returns cleanly, a found
//! ID is always a usable key that reads back through every written form, the size
//! bounds come first, and no message renders the input beyond one printable ASCII
//! character.
//!
//! ```text
//! cargo +nightly fuzz run invite target/fuzz-corpus/invite fuzz/seeds/invite -- -max_total_time=600
//! ```
//!
//! Corpus policy (decision M1-36): `fuzz/seeds/invite/` holds the committed seeds,
//! checked by `tornect_core::invite::tests::the_fuzz_seeds_answer_as_recorded`;
//! campaigns write to `target/fuzz-corpus/invite`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tornect_core::TornectId;
use tornect_core::invite::{self, Found, IdProblem, MAX_LINK, MAX_TEXT, Source};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let link = invite::parse_link(&text);
    let field = invite::find_id(&text);
    let _ = text.parse::<TornectId>();

    if let Ok(id) = link {
        assert!(id.verifying_key().is_ok());
        // A link that parses is what an ID field reads too (it holds nothing to strip).
        let as_link = Found {
            id,
            source: Source::Link,
            stripped: false,
        };
        assert_eq!(field, Ok(as_link));
    }
    if let Ok(found) = field {
        let id = found.id;
        assert!(id.verifying_key().is_ok());
        assert_eq!(invite::parse_link(&invite::link(&id)), Ok(id));
        let typed = Found {
            id,
            source: Source::Typed,
            stripped: false,
        };
        assert_eq!(invite::find_id(&id.display_groups()), Ok(typed));
        let invited = invite::find_id(&invite::invitation(&id));
        assert_eq!(invited.map(|f| (f.id, f.source)), Ok((id, Source::Text)));
    }
    if text.len() > MAX_LINK {
        assert_eq!(link, Err(IdProblem::LinkExtras));
    }
    if text.len() > MAX_TEXT {
        assert_eq!(field, Err(IdProblem::TooLong));
    }
    for problem in [link.err(), field.err()].into_iter().flatten() {
        let shown = problem.to_string();
        assert!(
            shown
                .chars()
                .all(|c| c.is_ascii_graphic() || matches!(c, ' ' | '–' | '“' | '”')),
            "{shown:?}"
        );
        assert!(!problem.name().is_empty());
    }
});
