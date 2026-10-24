//! The `mimeapps.list` edit of the Linux install (design `invite` §4.5):
//! text in, text out, no I/O. [`add`] names the link entry for `tornect:`
//! links, [`remove`] takes that out again; the file side is the Linux
//! module's.
//!
//! The file is the XDG MIME Applications spec's per-user list, shared with
//! GIO, KService and `xdg-mime`, so every byte the edit does not need to
//! change is kept: comments, unknown lines, other groups and keys, the line
//! endings (LF or CRLF) and a missing final newline. Lines are split with
//! `split_inclusive('\n')`; a group header is a line that reads `[…]` once
//! trimmed; a key line is `key=value` (spaces around `=` allowed), its value
//! a `;`-separated list. Only lines of the key `x-scheme-handler/tornect`
//! change, and only in the groups `[Added Associations]` and
//! `[Default Applications]`; `[Removed Associations]` is read, never
//! written.
//!
//! A line Tornect writes is exactly `x-scheme-handler/tornect=tornect-link.desktop;`:
//! lowercase, no spaces around `=` (`docs/research/links.md` finding 4: GIO
//! reads keys case-sensitively, generic `xdg-mime` only a line that starts
//! with `key=`). Removal matches the key in any ASCII case, so a variant is
//! cleaned too.
//!
//! [`remove`] after [`add`] gives back the exact bytes of a file that named
//! no `tornect-link.desktop` before, except in two shapes that every reader
//! takes for the same: an `[Added Associations]` or `[Default Applications]`
//! group that held only blank lines before is deleted, and an
//! `x-scheme-handler/tornect=` line whose list was empty is deleted once the
//! link entry is taken out of it again.

use super::{LINK_ENTRY, LINK_MIME, LinkHandler};

/// The group whose lines recommend a handler (GIO's "recommended", the
/// portal's single choice).
const ADDED: &str = "Added Associations";

/// The group whose lines choose the default handler.
const DEFAULT: &str = "Default Applications";

/// The group whose lines the user wrote to turn a handler off.
const REMOVED: &str = "Removed Associations";

/// The line Tornect writes in each of [`ADDED`] and [`DEFAULT`].
fn our_line() -> String {
    format!("{LINK_MIME}={LINK_ENTRY};")
}

/// One line of the file: its text, and its ending (`"\n"`, `"\r\n"`, or
/// nothing for a last line without one).
#[derive(Debug, Clone)]
struct Line {
    body: String,
    end: &'static str,
}

/// How a key is compared with `x-scheme-handler/tornect`.
#[derive(Clone, Copy)]
enum Key {
    /// Exactly, as GIO reads it.
    Exact,
    /// In any ASCII case.
    AnyCase,
}

/// The file as lines.
struct Doc {
    lines: Vec<Line>,
}

impl Doc {
    fn parse(text: &str) -> Self {
        let lines = text
            .split_inclusive('\n')
            .map(|l| {
                let (body, end) = if let Some(b) = l.strip_suffix("\r\n") {
                    (b, "\r\n")
                } else if let Some(b) = l.strip_suffix('\n') {
                    (b, "\n")
                } else {
                    (l, "")
                };
                Line {
                    body: body.to_owned(),
                    end,
                }
            })
            .collect();
        Self { lines }
    }

    fn text(&self) -> String {
        self.lines
            .iter()
            .flat_map(|l| [l.body.as_str(), l.end])
            .collect()
    }

    /// The ending new lines get: the file's first, else LF.
    fn eol(&self) -> &'static str {
        self.lines
            .iter()
            .map(|l| l.end)
            .find(|e| !e.is_empty())
            .unwrap_or("\n")
    }

    /// The group each line is in (`None` before the first header; a header
    /// is in its own group).
    fn groups(&self) -> Vec<Option<&str>> {
        let mut current = None;
        self.lines
            .iter()
            .map(|l| {
                if let Some(name) = header(&l.body) {
                    current = Some(name);
                }
                current
            })
            .collect()
    }

    /// The headers of `group`, in file order.
    fn headers(&self, group: &str) -> Vec<usize> {
        (0..self.lines.len())
            .filter(|&i| header(&self.lines[i].body) == Some(group))
            .collect()
    }

    /// The lines of the key `x-scheme-handler/tornect` in every `group`
    /// group, in file order.
    fn key_lines(&self, group: &str, key: Key) -> Vec<usize> {
        let groups = self.groups();
        (0..self.lines.len())
            .filter(|&i| groups[i] == Some(group) && ours(&self.lines[i].body, key).is_some())
            .collect()
    }

    /// The last line of the group whose header is at `at` that is not
    /// blank (the header itself when there is none).
    fn last_non_blank(&self, at: usize) -> usize {
        let mut last = at;
        for i in at + 1..self.lines.len() {
            let body = &self.lines[i].body;
            if header(body).is_some() {
                break;
            }
            if !body.trim().is_empty() {
                last = i;
            }
        }
        last
    }

    /// Insert `body` as a new line after line `at`; a last line without an
    /// ending gets one, and the new line goes without, so the file keeps
    /// its missing final newline.
    fn insert_after(&mut self, at: usize, body: String) {
        let eol = self.eol();
        let end = if self.lines[at].end.is_empty() {
            self.lines[at].end = eol;
            ""
        } else {
            eol
        };
        self.lines.insert(at + 1, Line { body, end });
    }

    /// Append the group `name` holding our line at the end of the file,
    /// after one blank line unless the file is empty.
    fn append_group(&mut self, name: &str) {
        let eol = self.eol();
        let unterminated = self.lines.last().is_some_and(|l| l.end.is_empty());
        if let Some(last) = self.lines.last_mut() {
            last.end = eol;
            self.lines.push(Line {
                body: String::new(),
                end: eol,
            });
        }
        self.lines.push(Line {
            body: format!("[{name}]"),
            end: eol,
        });
        self.lines.push(Line {
            body: our_line(),
            end: if unterminated { "" } else { eol },
        });
    }

    /// The value of the key line at `at`.
    fn value(&self, at: usize) -> &str {
        let body = &self.lines[at].body;
        body.split_once('=').map_or("", |(_, value)| value)
    }

    /// Replace the value of the key line at `at`, keeping its key and `=`
    /// as written.
    fn set_value(&mut self, at: usize, value: &str) {
        let body = &mut self.lines[at].body;
        if let Some(eq) = body.find('=') {
            body.truncate(eq + 1);
            body.push_str(value);
        }
    }
}

/// The group a header line opens, or `None` for any other line.
fn header(body: &str) -> Option<&str> {
    body.trim().strip_prefix('[')?.strip_suffix(']')
}

/// The value of `body` when it is a line of the key
/// `x-scheme-handler/tornect`, compared as `key` says.
fn ours(body: &str, key: Key) -> Option<&str> {
    if body.trim_start().starts_with('#') || header(body).is_some() {
        return None;
    }
    let (name, value) = body.split_once('=')?;
    let name = name.trim();
    let matches = match key {
        Key::Exact => name == LINK_MIME,
        Key::AnyCase => name.eq_ignore_ascii_case(LINK_MIME),
    };
    matches.then_some(value)
}

/// Whether the list `value` names the link entry.
fn lists_us(value: &str) -> bool {
    value.split(';').any(|item| item.trim() == LINK_ENTRY)
}

/// `value` with the link entry added as its last item, in the list's own
/// style: after a final `;` (and before any space after it) when there is
/// one, else after a `;` of its own.
fn appended(value: &str) -> String {
    match value.rfind(';') {
        Some(at) if value[at + 1..].trim().is_empty() => {
            format!("{}{LINK_ENTRY};{}", &value[..=at], &value[at + 1..])
        }
        _ if value.trim().is_empty() => format!("{LINK_ENTRY};{value}"),
        _ => format!("{value};{LINK_ENTRY}"),
    }
}

/// `value` without the link entry's items; `None` when the list is then
/// empty.
fn without_us(value: &str) -> Option<String> {
    let rest: Vec<&str> = value
        .split(';')
        .filter(|item| item.trim() != LINK_ENTRY)
        .collect();
    let rest = rest.join(";");
    rest.split(';')
        .any(|item| !item.trim().is_empty())
        .then_some(rest)
}

/// The first item of the list `value`.
fn first_item(value: &str) -> Option<&str> {
    value
        .split(';')
        .map(str::trim)
        .find(|item| !item.is_empty())
}

/// Name the link entry for `tornect:` links in the file `text` (empty for a
/// missing file): the new text, or `None` when nothing changes, and what
/// the file then says.
///
/// - A `[Removed Associations]` line of the key that lists the link entry:
///   nothing at all is written ([`LinkHandler::TurnedOff`]); the user turned
///   it off, and either group would override that.
/// - `[Added Associations]`: the key's line (the last one, which GIO reads)
///   gets the link entry appended to its list unless it lists it; with no
///   such line, our line goes after the group's last line that is not blank;
///   with no such group, the group goes at the end of the file, after one
///   blank line.
/// - `[Default Applications]`: a line of the key, in any case, is left as it
///   is ([`LinkHandler::Registered`] when its first item is the link entry,
///   else [`LinkHandler::OtherDefault`]); with none, our line is added as for
///   `[Added Associations]` ([`LinkHandler::Registered`]).
pub(crate) fn add(text: &str) -> (Option<String>, LinkHandler) {
    let mut doc = Doc::parse(text);
    let turned_off = doc
        .key_lines(REMOVED, Key::AnyCase)
        .into_iter()
        .any(|i| lists_us(doc.value(i)));
    if turned_off {
        return (None, LinkHandler::TurnedOff);
    }
    let mut changed = false;
    if let Some(&at) = doc.key_lines(ADDED, Key::Exact).last() {
        if !lists_us(doc.value(at)) {
            let value = appended(doc.value(at));
            doc.set_value(at, &value);
            changed = true;
        }
    } else if let Some(&at) = doc.headers(ADDED).first() {
        doc.insert_after(doc.last_non_blank(at), our_line());
        changed = true;
    } else {
        doc.append_group(ADDED);
        changed = true;
    }
    let handler = if let Some(&at) = doc.key_lines(DEFAULT, Key::AnyCase).last() {
        if first_item(doc.value(at)) == Some(LINK_ENTRY) {
            LinkHandler::Registered
        } else {
            LinkHandler::OtherDefault
        }
    } else {
        if let Some(&at) = doc.headers(DEFAULT).first() {
            doc.insert_after(doc.last_non_blank(at), our_line());
        } else {
            doc.append_group(DEFAULT);
        }
        changed = true;
        LinkHandler::Registered
    };
    (changed.then(|| doc.text()), handler)
}

/// Take the link entry out of the file `text`: from the list of every line
/// of the key `x-scheme-handler/tornect` (in any case) in every
/// `[Added Associations]` and `[Default Applications]` group, deleting a
/// line whose list is then empty; a group of those two left with only blank
/// lines is deleted, with the blank line before it. `[Removed
/// Associations]` is never touched. `None` when nothing names the link
/// entry; `Some("")` when nothing is left.
pub(crate) fn remove(text: &str) -> Option<String> {
    let mut doc = Doc::parse(text);
    let n = doc.lines.len();
    let mut drop = vec![false; n];
    let mut touched = Vec::new();
    for group in [ADDED, DEFAULT] {
        for at in doc.key_lines(group, Key::AnyCase) {
            let value = doc.value(at);
            if !lists_us(value) {
                continue;
            }
            match without_us(value) {
                Some(rest) => doc.set_value(at, &rest),
                None => drop[at] = true,
            }
            touched.push(group);
        }
    }
    if touched.is_empty() {
        return None;
    }
    for group in [ADDED, DEFAULT] {
        if !touched.contains(&group) {
            continue;
        }
        for at in doc.headers(group) {
            let only_blank = doc.lines[at + 1..]
                .iter()
                .enumerate()
                .take_while(|(_, l)| header(&l.body).is_none())
                .all(|(k, l)| drop[at + 1 + k] || l.body.trim().is_empty());
            if only_blank {
                drop[at] = true;
                if at > 0 && doc.lines[at - 1].body.trim().is_empty() {
                    drop[at - 1] = true;
                }
            }
        }
    }
    let unterminated = doc.lines.last().is_some_and(|l| l.end.is_empty());
    let last_dropped = drop.last().copied().unwrap_or(false);
    let mut kept: Vec<Line> = doc
        .lines
        .into_iter()
        .zip(drop)
        .filter_map(|(line, dropped)| (!dropped).then_some(line))
        .collect();
    if unterminated
        && last_dropped
        && let Some(last) = kept.last_mut()
    {
        last.end = "";
    }
    Some(Doc { lines: kept }.text())
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    const LINE: &str = "x-scheme-handler/tornect=tornect-link.desktop;";

    /// What a missing (or empty) file becomes.
    const BOTH: &str = "[Added Associations]\n\
                        x-scheme-handler/tornect=tornect-link.desktop;\n\
                        \n\
                        [Default Applications]\n\
                        x-scheme-handler/tornect=tornect-link.desktop;\n";

    fn added(text: &str) -> (String, LinkHandler) {
        let (new, handler) = add(text);
        (new.expect("a change"), handler)
    }

    /// A missing file gives exactly the two groups, each with the one line
    /// (lowercase key, no spaces: links.md finding 4).
    #[test]
    fn a_missing_file_gets_both_groups() {
        assert_eq!(our_line(), LINE);
        assert_eq!(add(""), (Some(BOTH.to_owned()), LinkHandler::Registered));
        assert_eq!(remove(BOTH).as_deref(), Some(""));
    }

    /// Comments, CRLF endings, other groups, unknown lines and a missing
    /// final newline stay byte for byte; only our lines are added, with the
    /// file's own ending, each after its group's last line that is not
    /// blank.
    #[test]
    fn only_our_lines_are_added() {
        let crlf = "# my associations\r\n\
                    [Default Applications]\r\n\
                    text/html=firefox.desktop;\r\n\
                    # keep me\r\n\
                    \r\n\
                    [Added Associations]\r\n\
                    text/plain=gedit.desktop;vim.desktop;\r\n\
                    \r\n\
                    [Other Group]\r\n\
                    weird line without equals\r\n";
        let (new, handler) = added(crlf);
        assert_eq!(handler, LinkHandler::Registered);
        assert_eq!(
            new,
            "# my associations\r\n\
             [Default Applications]\r\n\
             text/html=firefox.desktop;\r\n\
             # keep me\r\n\
             x-scheme-handler/tornect=tornect-link.desktop;\r\n\
             \r\n\
             [Added Associations]\r\n\
             text/plain=gedit.desktop;vim.desktop;\r\n\
             x-scheme-handler/tornect=tornect-link.desktop;\r\n\
             \r\n\
             [Other Group]\r\n\
             weird line without equals\r\n"
        );
        assert_eq!(remove(&new).as_deref(), Some(crlf));

        // No final newline: it stays missing, and comes back as it was.
        let bare = "[Default Applications]\ntext/html=firefox.desktop;";
        let (new, _) = added(bare);
        assert_eq!(
            new,
            format!(
                "[Default Applications]\ntext/html=firefox.desktop;\n{LINE}\n\n\
                 [Added Associations]\n{LINE}"
            )
        );
        assert_eq!(remove(&new).as_deref(), Some(bare));

        // A group of the key's name elsewhere is not one of ours.
        let other = "[Somewhere]\nx-scheme-handler/tornect=other.desktop;\n";
        let (new, handler) = added(other);
        assert_eq!(handler, LinkHandler::Registered);
        assert_eq!(new, format!("{other}\n{BOTH}"));
        assert_eq!(remove(&new).as_deref(), Some(other));
    }

    /// An `[Added Associations]` line of the key that names another program
    /// gets ours appended after it, in the list's own style; the other
    /// entries keep their order.
    #[test]
    fn an_added_line_of_another_program_gets_ours_appended() {
        for (value, with_ours) in [
            ("other.desktop;", "other.desktop;tornect-link.desktop;"),
            (
                "a.desktop;b.desktop;",
                "a.desktop;b.desktop;tornect-link.desktop;",
            ),
            ("other.desktop", "other.desktop;tornect-link.desktop"),
            ("other.desktop; ", "other.desktop;tornect-link.desktop; "),
            (
                " a.desktop; b.desktop;",
                " a.desktop; b.desktop;tornect-link.desktop;",
            ),
        ] {
            for sep in ["=", " = "] {
                let text = format!(
                    "[Added Associations]\nx-scheme-handler/tornect{sep}{value}\n\n\
                     [Default Applications]\n{LINE}\n"
                );
                let (new, handler) = added(&text);
                assert_eq!(handler, LinkHandler::Registered, "{value:?}");
                assert_eq!(
                    new,
                    format!(
                        "[Added Associations]\nx-scheme-handler/tornect{sep}{with_ours}\n\n\
                         [Default Applications]\n{LINE}\n"
                    ),
                    "{value:?}"
                );
            }
        }
        // A key in another case is not GIO's: ours goes beside it, exact.
        let text = "[Added Associations]\nX-Scheme-Handler/Tornect=other.desktop;\n";
        let (new, _) = added(text);
        assert!(
            new.starts_with(&format!(
                "[Added Associations]\nX-Scheme-Handler/Tornect=other.desktop;\n{LINE}\n"
            )),
            "{new}"
        );
    }

    /// A `[Default Applications]` line of the key, in any case and naming
    /// any program first, is never changed: another program first is
    /// `OtherDefault`, ours first is `Registered`.
    #[test]
    fn a_default_line_is_left_as_it_is() {
        for (line, handler) in [
            (
                "x-scheme-handler/tornect=other.desktop;",
                LinkHandler::OtherDefault,
            ),
            (
                "x-scheme-handler/tornect=other.desktop;tornect-link.desktop;",
                LinkHandler::OtherDefault,
            ),
            (
                "X-Scheme-Handler/Tornect=other.desktop;",
                LinkHandler::OtherDefault,
            ),
            (
                "x-scheme-handler/tornect = other.desktop",
                LinkHandler::OtherDefault,
            ),
            (
                "x-scheme-handler/tornect=tornect-link.desktop;other.desktop;",
                LinkHandler::Registered,
            ),
            (
                "x-scheme-handler/tornect=;tornect-link.desktop",
                LinkHandler::Registered,
            ),
        ] {
            let text = format!("[Default Applications]\n{line}\n");
            let (new, got) = added(&text);
            assert_eq!(got, handler, "{line}");
            assert_eq!(
                new,
                format!("[Default Applications]\n{line}\n\n[Added Associations]\n{LINE}\n"),
                "{line}"
            );
        }
    }

    /// `[Removed Associations]` listing the link entry for the key (in any
    /// case): nothing at all is written. Listing another program, or ours for
    /// another type, changes nothing about the install.
    #[test]
    fn a_removed_association_turns_it_off() {
        for text in [
            "[Removed Associations]\nx-scheme-handler/tornect=tornect-link.desktop;\n",
            "[Removed Associations]\nx-scheme-handler/tornect=a.desktop; tornect-link.desktop\n",
            "[Removed Associations]\nX-SCHEME-HANDLER/TORNECT=tornect-link.desktop;\n",
            "[Added Associations]\nx-scheme-handler/tornect=tornect-link.desktop;\n\n\
             [Removed Associations]\nx-scheme-handler/tornect=tornect-link.desktop;\n",
        ] {
            assert_eq!(add(text), (None, LinkHandler::TurnedOff), "{text}");
            // Removal never touches the group.
            let removed = remove(text);
            assert!(
                removed
                    .as_deref()
                    .unwrap_or(text)
                    .contains("[Removed Associations]\n"),
                "{text}"
            );
        }
        for text in [
            "[Removed Associations]\nx-scheme-handler/tornect=other.desktop;\n",
            "[Removed Associations]\ntext/plain=tornect-link.desktop;\n",
        ] {
            let (new, handler) = added(text);
            assert_eq!(handler, LinkHandler::Registered);
            assert_eq!(new, format!("{text}\n{BOTH}"));
        }
    }

    /// Adding to a file that already says it all changes nothing.
    #[test]
    fn adding_twice_changes_nothing_the_second_time() {
        for text in [
            "",
            "# c\n[Added Associations]\ntext/plain=a.desktop;\n",
            "[Default Applications]\nx-scheme-handler/tornect=other.desktop;\n",
            "[Added Associations]\nx-scheme-handler/tornect=other.desktop\n",
            "a\r\nb",
        ] {
            let (once, handler) = added(text);
            assert_eq!(add(&once), (None, handler), "{text:?}");
        }
    }

    /// `remove` takes out only the link entry: other programs' entries stay
    /// in order, a line left empty goes, a group left with only blank lines
    /// goes with the blank line before it, and `[Removed Associations]`
    /// stays.
    #[test]
    fn remove_takes_out_only_our_items() {
        let text = "[Added Associations]\n\
                    x-scheme-handler/tornect=a.desktop;tornect-link.desktop;b.desktop;\n\
                    text/plain=tornect-link.desktop;\n\
                    \n\
                    [Default Applications]\n\
                    X-Scheme-Handler/Tornect = tornect-link.desktop;\n\
                    \n\
                    [Removed Associations]\n\
                    x-scheme-handler/tornect=tornect-link.desktop;\n";
        assert_eq!(
            remove(text).as_deref(),
            Some(
                "[Added Associations]\n\
                 x-scheme-handler/tornect=a.desktop;b.desktop;\n\
                 text/plain=tornect-link.desktop;\n\
                 \n\
                 [Removed Associations]\n\
                 x-scheme-handler/tornect=tornect-link.desktop;\n"
            )
        );
        assert_eq!(
            remove("[Added Associations]\nx-scheme-handler/tornect=other.desktop;\n"),
            None
        );
        assert_eq!(remove(""), None);
        // Both lines of a duplicated group.
        assert_eq!(
            remove(&format!(
                "[Added Associations]\n{LINE}\n[Other]\nk=v\n[Added Associations]\n{LINE}\n"
            ))
            .as_deref(),
            Some("[Other]\nk=v\n")
        );
        // A comment keeps its group.
        assert_eq!(
            remove(&format!("[Added Associations]\n# mine\n{LINE}\n")).as_deref(),
            Some("[Added Associations]\n# mine\n")
        );
    }

    /// Add then remove gives back the exact bytes of files that never named
    /// the link entry.
    #[test]
    fn add_then_remove_gives_back_the_exact_bytes() {
        for text in [
            "",
            "\n",
            "# only a comment",
            "[Default Applications]\ntext/html=firefox.desktop;\n",
            "[Default Applications]\r\ntext/html=firefox.desktop;\r\n\r\n",
            "[Added Associations]\n# c\n\n\n[Default Applications]\nk=v",
            "[Added Associations]\nx-scheme-handler/tornect=other.desktop\n",
            "[Added Associations]\nx-scheme-handler/tornect= a.desktop ; \n",
            "[Default Applications]\nx-scheme-handler/tornect=other.desktop;\n",
            "  [Added Associations]  \n  text/plain=a.desktop;  \n",
        ] {
            let (new, _) = added(text);
            assert_eq!(remove(&new).as_deref(), Some(text), "{text:?}\n{new:?}");
        }
    }

    /// One line of a generated file.
    fn arb_line() -> impl Strategy<Value = String> {
        prop_oneof![
            Just(String::new()),
            Just("   ".to_owned()),
            "# [a-z ]{0,12}".prop_map(String::from),
            "[a-z]{1,8}/[a-z.+-]{1,10}=([a-z-]{1,8}\\.desktop;){1,3}",
            "x-scheme-handler/[a-z]{1,8}=[a-z]{1,8}\\.desktop;?",
            "(x-scheme-handler/tornect|X-Scheme-Handler/Tornect)( ?= ?)[a-z]{1,8}\\.desktop(;[a-z]{1,6}\\.desktop)?;?",
            "[A-Za-z0-9 =;.\\[\\]/é-]{0,20}",
        ]
    }

    /// A generated group: a header (one of the spec's three, or another
    /// name) and lines, with at least one line that is not blank.
    fn arb_group() -> impl Strategy<Value = Vec<String>> {
        (
            prop_oneof![
                Just("[Added Associations]".to_owned()),
                Just("[Default Applications]".to_owned()),
                Just("[Removed Associations]".to_owned()),
                "\\[[A-Za-z ]{1,12}\\]".prop_map(String::from),
            ],
            "[a-z]{1,6}=[a-z]{1,6}",
            proptest::collection::vec(arb_line(), 0..5),
        )
            .prop_map(|(head, first, mut rest)| {
                rest.insert(0, first);
                rest.insert(0, head);
                rest
            })
    }

    /// A generated `mimeapps.list` that never names the link entry, with LF
    /// or CRLF endings and with or without a final newline.
    fn arb_file() -> impl Strategy<Value = String> {
        (
            proptest::collection::vec(arb_line(), 0..3),
            proptest::collection::vec(arb_group(), 0..5),
            any::<bool>(),
            any::<bool>(),
        )
            .prop_map(|(lead, groups, crlf, final_eol)| {
                let lines: Vec<String> = lead
                    .into_iter()
                    .chain(groups.into_iter().flatten())
                    .collect();
                let eol = if crlf { "\r\n" } else { "\n" };
                let mut text = lines.join(eol);
                if final_eol && !text.is_empty() {
                    text.push_str(eol);
                }
                text
            })
            .prop_filter("names the link entry", |t| !t.contains(LINK_ENTRY))
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        /// Add then remove is the identity on files that never named the
        /// link entry; adding again changes nothing; the result names the
        /// link entry in `[Added Associations]` and has a default.
        #[test]
        fn add_and_remove_are_inverse(text in arb_file()) {
            let (new, handler) = add(&text);
            prop_assert_ne!(&handler, &LinkHandler::TurnedOff);
            let new = new.expect("a file that never named us changes");
            prop_assert_eq!(remove(&new), Some(text.clone()));
            prop_assert_eq!(add(&new), (None, handler.clone()));
            let doc = Doc::parse(&new);
            let at = *doc.key_lines(ADDED, Key::Exact).last().expect("an Added line");
            prop_assert!(lists_us(doc.value(at)));
            prop_assert!(!doc.key_lines(DEFAULT, Key::AnyCase).is_empty());
            if handler == LinkHandler::Registered && !text.to_ascii_lowercase().contains("[default applications]") {
                let header = format!("[Default Applications]{}", doc.eol());
                prop_assert!(new.contains(&header), "no Default group: {:?}", new);
            }
            // Only lines were added, and our key lines of `[Added Associations]` changed.
            let old = Doc::parse(&text);
            let kept: Vec<&str> = old.lines.iter().map(|l| l.body.as_str()).collect();
            let mut new_bodies = doc.lines.iter().map(|l| l.body.as_str());
            for body in kept {
                if ours(body, Key::Exact).is_some() {
                    continue;
                }
                prop_assert!(new_bodies.any(|b| b == body), "{:?} was lost", body);
            }
        }

        /// Any text at all is answered, never a panic, and the answers are
        /// consistent.
        #[test]
        fn any_text_is_answered(text in "(?s).{0,400}") {
            let (new, handler) = add(&text);
            if let Some(new) = &new {
                prop_assert!(new.contains(LINE));
                prop_assert_eq!(add(new).0, None);
                let removed = remove(new).unwrap_or_else(|| new.clone());
                let doc = Doc::parse(&removed);
                for group in [ADDED, DEFAULT] {
                    for at in doc.key_lines(group, Key::AnyCase) {
                        prop_assert!(!lists_us(doc.value(at)), "{:?}", removed);
                    }
                }
            } else {
                prop_assert!(handler == LinkHandler::TurnedOff || text.contains(LINK_ENTRY));
            }
            let _ = remove(&text);
        }
    }
}
