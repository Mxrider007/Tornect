//! The polkit policy the Linux zip ships (`packaging/polkit/org.tornect.policy`)
//! is the only thing that holds §B.8.6.2's "a fresh dialog per operation": the
//! client's ALWAYS_CHECK flag does not override a kept authorization
//! (`crates/tornect-platform/src/reauth.rs`), and root installs the file as
//! it is. So the gate reads the committed file and dist reads the copy it
//! stages, and both refuse anything but `auth_self` in every default of every
//! action, any action Tornect does not ask for, and any annotation.
//!
//! The file is read with a small XML reader of its own: a comment is dropped,
//! an internal DTD subset, an entity or a CDATA section is refused, so a value
//! can only be the literal text between two tags.

use std::collections::BTreeSet;

use anyhow::{Context as _, bail, ensure};

/// The committed policy, relative to the workspace root.
pub(crate) const SOURCE: &str = "packaging/polkit/org.tornect.policy";

/// The action ids `PolkitReAuth::action_for` can return. The platform test
/// `the_policy_file_declares_exactly_the_actions_the_client_asks_for` holds
/// the committed file to the client's list; [`check`] holds it, and the copy
/// dist stages, to this one.
pub(crate) const ACTIONS: [&str; 5] = [
    "org.tornect.grant",
    "org.tornect.enable",
    "org.tornect.autostart",
    "org.tornect.export",
    "org.tornect.settings",
];

/// The three implicit authorizations of an action's `<defaults>`.
const DEFAULTS: [&str; 3] = ["allow_any", "allow_inactive", "allow_active"];

/// The only value a default may have: the account's password, asked every
/// time. `auth_self_keep` keeps the answer for minutes, `yes` asks nothing,
/// `auth_admin*` asks an administrator instead of the person granting.
const VALUE: &str = "auth_self";

/// The gate's step: the committed policy passes [`check`].
pub(crate) fn check_committed(root: &std::path::Path) -> anyhow::Result<()> {
    println!("==> polkit policy ({SOURCE}): auth_self everywhere");
    let path = root.join(SOURCE);
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    check(SOURCE, &text)?;
    println!("    ok");
    Ok(())
}

/// Refuse a policy that would let an access-increasing operation pass
/// without a fresh password dialog (§B.8.6.2, §B.8.16): `name` is the file,
/// for the message.
pub(crate) fn check(name: &str, text: &str) -> anyhow::Result<()> {
    check_inner(text).with_context(|| {
        format!(
            "{name} is not the policy Tornect may ship: every default of every action must be \
             `{VALUE}` (a fresh password dialog per operation, docs/PLAN.md §B.8.6.2; the \
             client cannot enforce it), with exactly the actions {} and no annotation",
            ACTIONS.join(", ")
        )
    })
}

#[derive(Default)]
struct Action {
    id: String,
    defaults: usize,
    /// How many of each of [`DEFAULTS`] the action's `<defaults>` holds.
    counts: [usize; 3],
}

fn check_inner(text: &str) -> anyhow::Result<()> {
    let text = strip_comments(text)?;
    for banned in ["_keep", "policykit.imply", "<![CDATA[", "<!ENTITY"] {
        ensure!(
            !text.contains(banned),
            "`{banned}` appears outside a comment"
        );
    }
    let mut stack: Vec<&str> = Vec::new();
    let mut actions: Vec<Action> = Vec::new();
    // The default being read, and its text so far.
    let mut value: Option<(usize, String)> = None;
    for node in nodes(&text)? {
        match node {
            Node::Text(t) => {
                if let Some((_, v)) = value.as_mut() {
                    v.push_str(t);
                }
            }
            Node::Open { name, attrs, empty } => {
                ensure!(value.is_none(), "<{name}> inside a default");
                ensure!(
                    name != "annotate",
                    "an <annotate> (org.freedesktop.policykit.imply among them) can lend an \
                     action another's answer; the shipped policy has none"
                );
                let path = stack.as_slice();
                match name {
                    "policyconfig" => ensure!(path.is_empty(), "a nested <policyconfig>"),
                    "action" => {
                        ensure!(
                            path == ["policyconfig"],
                            "an <action> outside <policyconfig>"
                        );
                        let attributes = attributes(attrs)?;
                        let [("id", id)] = attributes.as_slice() else {
                            bail!("<action{attrs}>: an action has one attribute, its id");
                        };
                        ensure!(
                            ACTIONS.contains(id),
                            "action `{id}` is not one Tornect asks for"
                        );
                        ensure!(
                            !actions.iter().any(|a| a.id == *id),
                            "action `{id}` is declared twice"
                        );
                        actions.push(Action {
                            id: (*id).to_owned(),
                            ..Action::default()
                        });
                    }
                    "defaults" => {
                        ensure!(
                            path == ["policyconfig", "action"],
                            "a <defaults> outside an <action>"
                        );
                        if let Some(a) = actions.last_mut() {
                            a.defaults += 1;
                        }
                    }
                    _ => {
                        if let Some(i) = DEFAULTS.iter().position(|d| *d == name) {
                            ensure!(
                                path == ["policyconfig", "action", "defaults"],
                                "a <{name}> outside an action's <defaults>"
                            );
                            ensure!(!empty, "<{name}/> has no value");
                            value = Some((i, String::new()));
                        } else {
                            ensure!(!path.is_empty(), "the root element is <{name}>");
                        }
                    }
                }
                if !empty {
                    stack.push(name);
                }
            }
            Node::Close(name) => {
                ensure!(
                    stack.pop() == Some(name),
                    "</{name}> does not close the open element"
                );
                if let Some((i, v)) = value.take() {
                    ensure!(
                        v == VALUE,
                        "<{}> of `{}` is `{v}`",
                        DEFAULTS[i],
                        actions.last().map_or("", |a| a.id.as_str())
                    );
                    if let Some(a) = actions.last_mut() {
                        a.counts[i] += 1;
                    }
                }
            }
        }
    }
    ensure!(stack.is_empty(), "<{}> is not closed", stack.join("> <"));
    for a in &actions {
        ensure!(
            a.defaults == 1,
            "action `{}` has {} <defaults>, not one",
            a.id,
            a.defaults
        );
        for (d, n) in DEFAULTS.iter().zip(a.counts) {
            ensure!(n == 1, "action `{}` has {n} <{d}>, not one", a.id);
        }
    }
    let declared: BTreeSet<&str> = actions.iter().map(|a| a.id.as_str()).collect();
    let wanted: BTreeSet<&str> = ACTIONS.into_iter().collect();
    ensure!(
        declared == wanted,
        "the actions declared are {declared:?}, not {wanted:?}"
    );
    Ok(())
}

/// The text without its `<!-- … -->` comments.
fn strip_comments(text: &str) -> anyhow::Result<String> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("<!--") {
        out.push_str(&rest[..at]);
        let after = &rest[at + 4..];
        let end = after.find("-->").context("a comment is not closed")?;
        rest = &after[end + 3..];
    }
    out.push_str(rest);
    Ok(out)
}

#[derive(Debug, PartialEq, Eq)]
enum Node<'a> {
    Open {
        name: &'a str,
        /// Everything after the name, attributes and white space.
        attrs: &'a str,
        /// `<name/>`.
        empty: bool,
    },
    Close(&'a str),
    Text(&'a str),
}

/// The elements and text of a comment-free document; the XML declaration and
/// a DOCTYPE without an internal subset are passed over, any other `<!` or
/// `<?` is refused.
fn nodes(text: &str) -> anyhow::Result<Vec<Node<'_>>> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find('<') {
        out.push(Node::Text(&rest[..at]));
        let len = rest[at..]
            .find('>')
            .with_context(|| format!("a tag is not closed: `{}`", &rest[at..]))?;
        let inner = &rest[at + 1..at + len];
        rest = &rest[at + len + 1..];
        if let Some(pi) = inner.strip_prefix('?') {
            ensure!(
                pi.starts_with("xml ") && pi.ends_with('?'),
                "`<{inner}>`: no processing instruction belongs here"
            );
            continue;
        }
        if let Some(doctype) = inner.strip_prefix("!DOCTYPE") {
            ensure!(
                !doctype.contains('['),
                "the DOCTYPE has an internal subset, which can declare entities"
            );
            continue;
        }
        ensure!(!inner.starts_with('!'), "`<{inner}>` is refused");
        if let Some(name) = inner.strip_prefix('/') {
            out.push(Node::Close(name.trim_end()));
            continue;
        }
        let (inner, empty) = match inner.strip_suffix('/') {
            Some(i) => (i, true),
            None => (inner, false),
        };
        let end = inner.find(char::is_whitespace).unwrap_or(inner.len());
        ensure!(end > 0, "`<{inner}>` has no element name");
        out.push(Node::Open {
            name: &inner[..end],
            attrs: &inner[end..],
            empty,
        });
    }
    out.push(Node::Text(rest));
    Ok(out)
}

/// `name="value"` pairs, either quote.
fn attributes(attrs: &str) -> anyhow::Result<Vec<(&str, &str)>> {
    let mut out = Vec::new();
    let mut rest = attrs.trim_start();
    while !rest.is_empty() {
        let eq = rest
            .find('=')
            .with_context(|| format!("`{rest}` is not an attribute"))?;
        let name = rest[..eq].trim();
        let after = rest[eq + 1..].trim_start();
        let quote = after
            .chars()
            .next()
            .filter(|c| *c == '"' || *c == '\'')
            .with_context(|| format!("attribute `{name}` is not quoted"))?;
        let end = after[1..]
            .find(quote)
            .with_context(|| format!("attribute `{name}` is not closed"))?;
        out.push((name, &after[1..=end]));
        rest = after[end + 2..].trim_start();
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn committed() -> String {
        let root = crate::workspace_root().unwrap();
        std::fs::read_to_string(root.join(SOURCE)).unwrap()
    }

    /// The committed policy passes, through the gate's own step too.
    #[test]
    fn the_committed_policy_passes() {
        check(SOURCE, &committed()).unwrap();
        check_committed(&crate::workspace_root().unwrap()).unwrap();
    }

    /// The security review of the documentation pass (major): every change
    /// that would let an operation pass without a fresh password dialog is
    /// refused, wherever in the file it is made.
    #[test]
    fn a_policy_that_weakens_auth_self_is_refused() {
        let good = committed();
        let first = "<allow_active>auth_self</allow_active>";
        let last = "<allow_any>auth_self</allow_any>";
        assert!(good.contains(first) && good.contains(last));
        let once = |from: &str, to: &str| good.replacen(from, to, 1);
        let last_one = |from: &str, to: &str| {
            let at = good.rfind(from).unwrap();
            format!("{}{to}{}", &good[..at], &good[at + from.len()..])
        };
        let annotate = "<annotate key=\"org.freedesktop.policykit.imply\">org.tornect.settings\
                        </annotate>";
        let cases: Vec<(&str, String)> = vec![
            (
                "auth_self_keep",
                once(first, "<allow_active>auth_self_keep</allow_active>"),
            ),
            ("yes", once(first, "<allow_active>yes</allow_active>")),
            ("yes, last", last_one(last, "<allow_any>yes</allow_any>")),
            (
                "auth_admin",
                once(first, "<allow_active>auth_admin</allow_active>"),
            ),
            (
                "auth_admin_keep",
                once(first, "<allow_active>auth_admin_keep</allow_active>"),
            ),
            ("no", once(first, "<allow_active>no</allow_active>")),
            (
                "white space",
                once(first, "<allow_active> auth_self </allow_active>"),
            ),
            ("empty", once(first, "<allow_active/>")),
            (
                "space in the tag",
                once(first, "<allow_active >yes</allow_active >"),
            ),
            (
                "a second allow_active",
                once(first, &format!("{first}{first}")),
            ),
            ("no allow_active", once(first, "")),
            (
                "an element in the value",
                once(first, "<allow_active><x/>auth_self</allow_active>"),
            ),
            (
                "imply",
                once("</defaults>", &format!("</defaults>{annotate}")),
            ),
            (
                "imply, own line",
                once("<defaults>", &format!("{annotate}<defaults>")),
            ),
            (
                "a default outside <defaults>",
                once("</defaults>", &format!("</defaults>{first}")),
            ),
            (
                "another annotation",
                once(
                    "<defaults>",
                    "<annotate key=\"org.freedesktop.policykit.exec.path\">/bin/sh</annotate>\
                     <defaults>",
                ),
            ),
            (
                "a second <defaults>",
                once(
                    "</defaults>",
                    "</defaults><defaults><allow_active>auth_self</allow_active></defaults>",
                ),
            ),
            (
                "an action Tornect does not ask for",
                once("org.tornect.grant\"", "org.tornect.anything\""),
            ),
            (
                "a duplicate action",
                once("org.tornect.enable\"", "org.tornect.grant\""),
            ),
            (
                "a second attribute",
                once(
                    "<action id=\"org.tornect.grant\">",
                    "<action id=\"org.tornect.grant\" x=\"y\">",
                ),
            ),
            (
                "an entity",
                once(
                    "\"http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd\">",
                    "\"http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd\" \
                     [<!ENTITY s \"yes\">]>",
                ),
            ),
            (
                "a CDATA value",
                once(first, "<allow_active><![CDATA[yes]]></allow_active>"),
            ),
            ("an unclosed comment", once("<vendor>", "<!-- <vendor>")),
        ];
        for (what, text) in &cases {
            assert_ne!(text, &good, "{what}: the edit did not apply");
            let refused = check("P", text).expect_err(what);
            assert!(
                format!("{refused:#}").starts_with("P is not the policy Tornect may ship"),
                "{what}: {refused:#}"
            );
        }

        // An action removed whole.
        let start = good.find("<action id=\"org.tornect.export\">").unwrap();
        let end = start + good[start..].find("</action>").unwrap() + "</action>".len();
        let without = format!("{}{}", &good[..start], &good[end..]);
        assert!(check("P", &without).is_err());
    }

    /// What is refused is refused for its content: the warnings the file
    /// carries in its comment, and white space in the layout, pass.
    #[test]
    fn comments_and_layout_do_not_count() {
        let good = committed();
        assert!(
            good.contains("auth_self_keep"),
            "the file's warning is gone"
        );
        let relaid = good
            .replace("<defaults>", "<defaults >\n")
            .replace("</action>", "</action\n>");
        check("P", &relaid).unwrap();
        let commented = good.replacen(
            "<vendor>",
            "<!-- <allow_active>yes</allow_active> org.freedesktop.policykit.imply --><vendor>",
            1,
        );
        check("P", &commented).unwrap();
    }

    #[test]
    fn attributes_read_either_quote() {
        assert_eq!(
            attributes(" id=\"a.b\"  x = 'c d' ").unwrap(),
            [("id", "a.b"), ("x", "c d")]
        );
        assert!(attributes(" id=a").is_err());
        assert!(attributes(" id=\"a").is_err());
        assert!(attributes("").unwrap().is_empty());
    }
}
