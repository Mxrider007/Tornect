//! `THIRD_PARTY_LICENSES.txt`, the licence texts each release zip carries
//! (`docs/RELEASING.md`, "What must be true before a tag", item 7). `cargo
//! xtask dist` writes it per platform, offline, from what the build machine
//! already holds:
//!
//! * the crates.io packages that `cargo build -p tornect --target <triple>`
//!   builds (`cargo tree -e normal,build`), each with its version and licence
//!   expression, marked `linked` when its code is in the executable (the same
//!   graph without build dependencies and procedural macros) or `build` when
//!   it only runs while the executable is built;
//! * each package's own licence files as published: the files at the root of
//!   its source whose names begin with LICENSE, LICENCE, COPYING, COPYRIGHT,
//!   NOTICE or UNLICENSE, its `license-file`, and a root `LICENSES/` folder;
//! * for a package that publishes none, the canonical text of each licence its
//!   expression names (`packaging/licenses/`, whose `SOURCES.md` says where
//!   each text came from), with the authors its manifest names;
//! * code compiled in under a licence of its own that is no crate's own: the C
//!   sources and fonts inside some crates (`BUNDLED`), the Rust standard
//!   library, and on Windows llvm-mingw's runtime; and pointers to lyrebird's
//!   notices (`pt/lyrebird.txt`) and to Tornect's own
//!   (`THIRD_PARTY_NOTICES.md`).
//!
//! Identical texts are written once and numbered; each package's line gives
//! the numbers of its texts.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail, ensure};

/// The file's name in each zip.
pub const FILE: &str = "THIRD_PARTY_LICENSES.txt";

/// Canonical licence texts, `<SPDX id>.txt`, for packages that publish no
/// licence file of their own.
pub const CANONICAL: &str = "packaging/licenses";

/// A file at the root of a package whose upper-cased name begins with one of
/// these is one of its licence files.
const LICENCE_FILE_PREFIXES: [&str; 6] = [
    "LICENSE",
    "LICENCE",
    "COPYING",
    "COPYRIGHT",
    "NOTICE",
    "UNLICENSE",
];

/// Code inside a crate's published source that the build compiles in under a
/// licence of its own, and the files of that source that carry the licence.
pub struct Bundled {
    pub krate: &'static str,
    pub what: &'static str,
    pub files: &'static [&'static str],
}

pub const BUNDLED: [Bundled; 6] = [
    Bundled {
        krate: "openh264-sys2",
        what: "Cisco OpenH264, the H.264 encoder and decoder (C++ and assembly, from the \
               crate's upstream/): BSD-2-Clause",
        files: &["upstream/LICENSE"],
    },
    Bundled {
        krate: "ring",
        what: "fiat-crypto's field arithmetic inside ring (C, from its third_party/fiat/): \
               Apache-2.0",
        files: &["third_party/fiat/LICENSE"],
    },
    Bundled {
        krate: "zstd-sys",
        what: "Zstandard (C, from the crate's zstd/): BSD-3-Clause, the one of its two \
               licences (BSD or GPL-2.0) that this build uses",
        files: &["zstd/LICENSE"],
    },
    Bundled {
        krate: "liblzma-sys",
        what: "liblzma of XZ Utils (C, from the crate's xz/): 0BSD",
        files: &["xz/COPYING", "xz/COPYING.0BSD"],
    },
    Bundled {
        krate: "libsqlite3-sys",
        what: "SQLite (C, from the crate's sqlite3/): in the public domain, so no licence \
               text applies",
        files: &[],
    },
    Bundled {
        krate: "epaint_default_fonts",
        what: "the fonts of the window: Ubuntu Light (Ubuntu Font Licence 1.0), Hack (MIT, \
               with its DejaVu and Bitstream Vera parts under their own terms), Noto Emoji \
               (SIL Open Font License 1.1) and emoji-icon-font (MIT)",
        files: &[
            "fonts/UFL.txt",
            "fonts/Hack-Regular.txt",
            "fonts/OFL.txt",
            "fonts/emoji-icon-font-mit-license.txt",
        ],
    },
];

/// A crates.io package of the build graph.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Package {
    pub name: String,
    pub version: String,
    /// The `license` expression of its manifest, as `cargo tree` prints it.
    pub licence: String,
    /// Its code is in the executable; otherwise it only runs during the build.
    pub linked: bool,
}

/// The crates.io packages `cargo build -p tornect --target <triple>` builds.
pub fn graph(root: &Path, triple: &str) -> anyhow::Result<Vec<Package>> {
    let all = tree(root, triple, "normal,build")?;
    let linked = tree(root, triple, "normal,no-proc-macro")?;
    ensure!(
        linked.is_subset(&all),
        "cargo tree: the linked packages for {triple} are not all in its build graph"
    );
    Ok(all
        .into_iter()
        .map(|(name, version, licence)| {
            let linked = linked.contains(&(name.clone(), version.clone(), licence.clone()));
            Package {
                name,
                version,
                licence,
                linked,
            }
        })
        .collect())
}

type TreeEntry = (String, String, String);

fn tree(root: &Path, triple: &str, edges: &str) -> anyhow::Result<BTreeSet<TreeEntry>> {
    let out = crate::cargo()
        .args([
            "tree", "--locked", "-p", "tornect", "--target", triple, "-e", edges,
        ])
        .args(["--prefix", "none", "--format", "{p}|{l}"])
        .current_dir(root)
        .output()
        .context("spawning `cargo tree`")?;
    ensure!(
        out.status.success(),
        "`cargo tree --target {triple} -e {edges}` failed ({}): {}",
        out.status,
        String::from_utf8_lossy(&out.stderr).trim()
    );
    let mut set = BTreeSet::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if let Some(entry) = parse_tree_line(line, root)? {
            set.insert(entry);
        }
    }
    ensure!(
        !set.is_empty(),
        "`cargo tree` listed no crates.io package for {triple}"
    );
    Ok(set)
}

/// A `cargo tree --prefix none --format '{p}|{l}'` line: `name vX.Y.Z|licence`,
/// with ` (proc-macro)` after the version of a procedural macro, a path there
/// for the workspace's own packages (`None`: Tornect's own, `LICENSE`), and
/// ` (*)` at the end of a package already listed.
fn parse_tree_line(line: &str, root: &Path) -> anyhow::Result<Option<TreeEntry>> {
    let line = line.trim_end();
    let line = line.strip_suffix(" (*)").unwrap_or(line);
    if line.is_empty() {
        return Ok(None);
    }
    let (package, licence) = line
        .split_once('|')
        .with_context(|| format!("unexpected `cargo tree` line `{line}`"))?;
    let (name, rest) = package
        .split_once(" v")
        .with_context(|| format!("unexpected `cargo tree` package `{package}`"))?;
    let (version, source) = rest.split_once(' ').unwrap_or((rest, ""));
    let source = source.strip_suffix(" (proc-macro)").unwrap_or(source);
    match source {
        "" | "(proc-macro)" => Ok(Some((
            name.to_owned(),
            version.to_owned(),
            licence.trim().to_owned(),
        ))),
        path if path
            .strip_prefix('(')
            .and_then(|p| p.strip_suffix(')'))
            .is_some_and(|p| Path::new(p).starts_with(root)) =>
        {
            Ok(None)
        }
        other => bail!("{name} {version} comes from {other}, not from crates.io"),
    }
}

/// The licence identifiers an SPDX expression names, `WITH` exceptions
/// included. `-only`, `-or-later` and `+` are dropped (one text serves them),
/// and the old `/` separator counts as `OR`.
pub fn licence_ids(expression: &str) -> Vec<String> {
    let mut ids = BTreeSet::new();
    for word in expression.split(|c: char| c.is_whitespace() || matches!(c, '(' | ')' | '/')) {
        if word.is_empty() || matches!(word, "AND" | "OR" | "WITH") {
            continue;
        }
        let id = word.trim_end_matches('+');
        let id = id
            .strip_suffix("-only")
            .or_else(|| id.strip_suffix("-or-later"))
            .unwrap_or(id);
        ids.insert(id.to_owned());
    }
    ids.into_iter().collect()
}

/// `$CARGO_HOME/registry/src/<crates.io index>/`, where cargo unpacks sources.
fn registry_sources() -> anyhow::Result<Vec<PathBuf>> {
    let home = crate::cargo_home().context("neither CARGO_HOME nor HOME is set")?;
    let src = home.join("registry").join("src");
    let mut dirs: Vec<PathBuf> = fs::read_dir(&src)
        .with_context(|| format!("reading {}", src.display()))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.is_dir()
                && p.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with("index.crates.io-"))
        })
        .collect();
    dirs.sort();
    ensure!(
        !dirs.is_empty(),
        "no crates.io sources under {}: build first",
        src.display()
    );
    Ok(dirs)
}

fn source_dir(registry: &[PathBuf], package: &Package) -> anyhow::Result<PathBuf> {
    let leaf = format!("{}-{}", package.name, package.version);
    registry
        .iter()
        .map(|r| r.join(&leaf))
        .find(|d| d.join("Cargo.toml").is_file())
        .with_context(|| {
            format!(
                "the source of {} {} is not under $CARGO_HOME/registry/src/ (run `cargo fetch`)",
                package.name, package.version
            )
        })
}

/// A package's own licence files, relative to its source directory.
fn own_files(dir: &Path) -> anyhow::Result<Vec<String>> {
    let mut files = BTreeSet::new();
    for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let upper = name.to_ascii_uppercase();
        let path = entry.path();
        if path.is_file() && LICENCE_FILE_PREFIXES.iter().any(|p| upper.starts_with(p)) {
            files.insert(name);
        } else if path.is_dir() && matches!(upper.as_str(), "LICENSES" | "LICENCES") {
            for inner in fs::read_dir(&path)? {
                let inner = inner?;
                if inner.path().is_file() {
                    files.insert(format!("{name}/{}", inner.file_name().to_string_lossy()));
                }
            }
        }
    }
    let manifest = fs::read_to_string(dir.join("Cargo.toml"))
        .with_context(|| format!("reading {}", dir.join("Cargo.toml").display()))?;
    if let Some(declared) = package_field(&manifest, "license-file") {
        let declared = declared.trim_start_matches("./").to_owned();
        if dir.join(&declared).is_file() {
            files.insert(declared);
        }
    }
    Ok(files.into_iter().collect())
}

/// A string field of a manifest's `[package]` table, as cargo writes it
/// (`key = "value"` on one line).
fn package_field(manifest: &str, key: &str) -> Option<String> {
    package_table(manifest).find_map(|line| {
        let rest = line
            .strip_prefix(key)?
            .trim_start()
            .strip_prefix('=')?
            .trim();
        Some(rest.strip_prefix('"')?.strip_suffix('"')?.to_owned())
    })
}

fn package_table(manifest: &str) -> impl Iterator<Item = &str> {
    manifest
        .lines()
        .map(str::trim)
        .skip_while(|l| *l != "[package]")
        .skip(1)
        .take_while(|l| !l.starts_with('['))
}

/// The `authors` of a manifest's `[package]` table, without e-mail addresses.
fn authors(manifest: &str) -> Option<String> {
    let mut lines = package_table(manifest);
    let first = lines.find(|l| l.starts_with("authors"))?;
    let mut array = first.split_once('=')?.1.trim().to_owned();
    while !array.contains(']') {
        array.push_str(lines.next()?);
    }
    let names: Vec<String> = array
        .split('"')
        .skip(1)
        .step_by(2)
        .map(|a| match a.split_once('<') {
            Some((name, _)) => name.trim().to_owned(),
            None => a.trim().to_owned(),
        })
        .filter(|a| !a.is_empty())
        .collect();
    (!names.is_empty()).then(|| names.join(", "))
}

/// A licence text as one line ending: LF, no trailing blanks, no BOM.
fn normalise(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    let text = text.trim_start_matches('\u{feff}');
    let lines: Vec<&str> = text
        .split('\n')
        .map(|l| l.trim_end_matches(['\r', ' ', '\t']))
        .collect();
    lines.join("\n").trim_matches('\n').to_owned()
}

fn read_text(path: &Path) -> anyhow::Result<String> {
    let raw = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(normalise(&raw))
}

/// A text of part 3.
struct Text {
    origin: String,
    body: String,
    /// How many places published exactly this text.
    shared: usize,
}

/// The texts in order of first use, each distinct body once.
#[derive(Default)]
struct Texts {
    list: Vec<Text>,
    index: BTreeMap<String, usize>,
}

impl Texts {
    /// The text's number (from 1), adding it if it is new.
    fn add(&mut self, origin: String, body: String) -> usize {
        if let Some(&i) = self.index.get(&body) {
            self.list[i].shared += 1;
            return i + 1;
        }
        self.index.insert(body.clone(), self.list.len());
        self.list.push(Text {
            origin,
            body,
            shared: 1,
        });
        self.list.len()
    }
}

/// A package's line in part 2.
pub struct Entry {
    pub package: Package,
    /// Canonical texts stand in: the package publishes no licence file.
    pub canonical: bool,
    pub authors: Option<String>,
    /// The numbers of its texts.
    pub texts: Vec<usize>,
}

/// An item of part 1.
struct Item {
    what: String,
    texts: Vec<usize>,
}

/// The toolchain parts the executable links, for part 1.
pub struct Toolchain<'a> {
    /// The first line of `rustc -vV`.
    pub rustc: &'a str,
    /// `rustc --print sysroot`.
    pub sysroot: &'a Path,
    /// llvm-mingw's directory, for a Windows executable.
    pub mingw: Option<&'a Path>,
}

/// llvm-mingw's runtime that a Windows executable links statically (`dist`'s
/// `LLVM_MINGW_LINKED`) and the files that carry its licences.
const MINGW_RUNTIME: [(&str, &str); 2] = [
    (
        "LICENSE.TXT",
        "libc++, libc++abi, libunwind and compiler-rt's builtins, from the LLVM project: \
         Apache-2.0 WITH LLVM-exception",
    ),
    (
        "x86_64-w64-mingw32/share/mingw32/COPYING.MinGW-w64-runtime.txt",
        "the mingw-w64 runtime's start-up and support code (crt2.o, libmingw32.a, \
         libmingwex.a): the notices mingw-w64 asks a statically linked program to carry \
         (ZPL-2.1 overall; getopt, gdtoa, parts of the maths library and some string and \
         time functions under their own permissive terms)",
    ),
];

/// Everything the file says for one platform.
pub struct Licences {
    items: Vec<Item>,
    pub entries: Vec<Entry>,
    texts: Texts,
}

impl Licences {
    /// The number of distinct texts in part 3.
    pub fn texts(&self) -> usize {
        self.texts.list.len()
    }

    /// The number of items in part 1 before the two pointers.
    pub fn items(&self) -> usize {
        self.items.len()
    }
}

/// Collect the licences for `triple`; `toolchain` adds the standard library and
/// llvm-mingw's runtime (the gate's test leaves them out).
pub fn collect(
    root: &Path,
    triple: &str,
    toolchain: Option<&Toolchain<'_>>,
) -> anyhow::Result<Licences> {
    let packages = graph(root, triple)?;
    let registry = registry_sources()?;
    let mut texts = Texts::default();
    let mut items = Vec::new();

    if let Some(tc) = toolchain {
        let notices = tc
            .sysroot
            .join("share")
            .join("doc")
            .join("rust")
            .join("COPYRIGHT-library.html");
        let html = fs::read_to_string(&notices).with_context(|| {
            format!(
                "reading {} (the Rust standard library's notices; `rustup component add \
                 rust-docs` installs them)",
                notices.display()
            )
        })?;
        let n = texts.add(
            format!(
                "The Rust standard library's notices: COPYRIGHT-library.html of {}, as \
                 plain text",
                tc.rustc
            ),
            html_to_text(&html),
        );
        items.push(Item {
            what: format!(
                "The Rust standard library of {}, linked into every Rust program: \
                 Apache-2.0 OR MIT, with the notices of the files and crates it is built from",
                tc.rustc
            ),
            texts: vec![n],
        });
        if let Some(mingw) = tc.mingw {
            for (file, what) in MINGW_RUNTIME {
                let n = texts.add(
                    format!("{file} of llvm-mingw"),
                    read_text(&mingw.join(file))?,
                );
                items.push(Item {
                    what: format!("llvm-mingw's runtime, linked statically: {what}"),
                    texts: vec![n],
                });
            }
        }
    }

    for bundled in &BUNDLED {
        let Some(package) = packages.iter().find(|p| p.name == bundled.krate) else {
            continue;
        };
        let dir = source_dir(&registry, package)?;
        let mut numbers = Vec::new();
        for file in bundled.files {
            numbers.push(texts.add(
                format!("{file} of {} {}", package.name, package.version),
                read_text(&dir.join(file))?,
            ));
        }
        items.push(Item {
            what: format!("{} (in {} {})", bundled.what, package.name, package.version),
            texts: numbers,
        });
    }

    let mut entries = Vec::new();
    for package in packages {
        let dir = source_dir(&registry, &package)?;
        let own = own_files(&dir)?;
        let mut numbers = Vec::new();
        for file in &own {
            let body = read_text(&dir.join(file))?;
            if !body.is_empty() {
                numbers.push(texts.add(
                    format!("{file} of {} {}", package.name, package.version),
                    body,
                ));
            }
        }
        let canonical = numbers.is_empty();
        let mut authors_line = None;
        if canonical {
            for id in licence_ids(&package.licence) {
                let path = root.join(CANONICAL).join(format!("{id}.txt"));
                ensure!(
                    path.is_file(),
                    "{} {} publishes no licence file and {CANONICAL}/ has no canonical text \
                     of {id}: add {id}.txt there (and its row in SOURCES.md)",
                    package.name,
                    package.version
                );
                numbers.push(texts.add(
                    format!(
                        "the canonical text of {id} ({CANONICAL}/{id}.txt in Tornect's source)"
                    ),
                    read_text(&path)?,
                ));
            }
            let manifest = fs::read_to_string(dir.join("Cargo.toml"))?;
            authors_line = authors(&manifest);
        }
        ensure!(
            !numbers.is_empty(),
            "{} {} has no licence text: it publishes none and its expression `{}` names no \
             licence",
            package.name,
            package.version,
            package.licence
        );
        numbers.sort_unstable();
        numbers.dedup();
        entries.push(Entry {
            package,
            canonical,
            authors: authors_line,
            texts: numbers,
        });
    }
    Ok(Licences {
        items,
        entries,
        texts,
    })
}

/// What part 1's header names.
pub struct Heading<'a> {
    pub version: &'a str,
    pub title: &'a str,
    pub triple: &'a str,
    pub exe: &'a str,
    /// The zip's name for lyrebird: `pt/lyrebird` or `pt/lyrebird.exe`.
    pub lyrebird: &'a str,
}

/// The file's text.
pub fn render(l: &Licences, h: &Heading<'_>) -> String {
    let linked = l.entries.iter().filter(|e| e.package.linked).count();
    let build = l.entries.len() - linked;
    let refs = |numbers: &[usize]| -> String {
        numbers
            .iter()
            .map(|n| format!("[{n}]"))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let mut s = String::new();
    let title = format!(
        "Third-party licences in Tornect {} for {} ({})",
        h.version, h.title, h.triple
    );
    let _ = writeln!(s, "{title}\n{}\n", "=".repeat(title.chars().count()));
    let _ = writeln!(
        s,
        "Tornect is free software under the GNU General Public License, version 3 or later\n\
         (LICENSE). {exe} also contains the third-party code below, each part under its own\n\
         licence. This file names every part and gives the licence texts they come with, as\n\
         those licences ask of a program that is passed on. `cargo xtask dist` wrote it from\n\
         this platform's dependency graph in Cargo.lock and the published sources of the\n\
         crates (docs/RELEASING.md in Tornect's source).\n\n\
         \x20 Part 1  code that is not a Rust crate of its own\n\
         \x20 Part 2  the {n} Rust crates from crates.io: {linked} linked into {exe}, {build} that only\n\
         \x20         run while it is built\n\
         \x20 Part 3  the licence texts: {t} different texts, each given once, numbered [1] to [{t}]\n",
        exe = h.exe,
        n = l.entries.len(),
        t = l.texts.list.len(),
    );

    let _ = writeln!(
        s,
        "\nPart 1. Code that is not a Rust crate of its own\n\
         ================================================\n"
    );
    let mut bullets: Vec<String> = l
        .items
        .iter()
        .map(|item| match item.texts.as_slice() {
            [] => format!("{}.", item.what),
            numbers => format!("{}: {}", item.what, refs(numbers)),
        })
        .collect();
    bullets.push(format!(
        "lyrebird {} ({}), a program of its own from the tor-expert-bundle of Tor Browser {}: \
         {}.txt next to it holds its licence notices and those of the Go modules built into \
         it, as the Tor Project publishes them.",
        crate::pt::LYREBIRD_VERSION,
        h.lyrebird,
        crate::pt::TOR_BROWSER,
        h.lyrebird.trim_end_matches(".exe"),
    ));
    bullets.push(
        "Third-party material in Tornect's own source (Chromium's key-code table): \
         THIRD_PARTY_NOTICES.md."
            .to_owned(),
    );
    for bullet in &bullets {
        let _ = writeln!(s, "{}\n", wrap(bullet, 90, "* ", "  "));
    }

    let _ = writeln!(
        s,
        "\nPart 2. Rust crates\n===================\n\n\
         Each line: the crate, its version, `linked` (its code is in {exe}) or `build` (it only\n\
         runs while {exe} is built: build scripts, procedural macros and what they use), its\n\
         licence expression, and the numbers of its texts in part 3. A crate that publishes no\n\
         licence file is marked `canonical`: the canonical text of each licence it names stands\n\
         in, with the authors its manifest names. The source of each crate, as built, is at\n\
         https://crates.io/crates/<crate>/<version>.\n",
        exe = h.exe
    );
    for e in &l.entries {
        let p = &e.package;
        let _ = write!(
            s,
            "{} {}  {}  {}  {}",
            p.name,
            p.version,
            if p.linked { "linked" } else { "build" },
            p.licence,
            refs(&e.texts)
        );
        if e.canonical {
            let _ = write!(s, "  canonical");
            if let Some(authors) = &e.authors {
                let _ = write!(s, "; authors: {authors}");
            }
        }
        s.push('\n');
    }

    let _ = writeln!(s, "\n\nPart 3. Licence texts\n=====================");
    let rule = "-".repeat(78);
    for (i, text) in l.texts.list.iter().enumerate() {
        let also = match text.shared {
            1 => String::new(),
            2 => ", and the same text in 1 other place".to_owned(),
            n => format!(", and the same text in {} other places", n - 1),
        };
        let _ = writeln!(s, "\n{rule}\n[{}] {}{also}\n{rule}\n", i + 1, text.origin);
        let _ = writeln!(s, "{}", text.body);
    }
    s
}

/// `text` in lines of at most `width` characters where its words allow,
/// behind `first` on the first line and `rest` on the others.
fn wrap(text: &str, width: usize, first: &str, rest: &str) -> String {
    let mut out = String::from(first);
    let mut column = first.chars().count();
    let mut empty = true;
    for word in text.split_whitespace() {
        let len = word.chars().count();
        if !empty && column + 1 + len > width {
            out.push('\n');
            out.push_str(rest);
            column = rest.chars().count();
            empty = true;
        }
        if !empty {
            out.push(' ');
            column += 1;
        }
        out.push_str(word);
        column += len;
        empty = false;
    }
    out
}

/// The toolchain's `COPYRIGHT-library.html` as plain text: tags dropped, the
/// ends of blocks turned into line breaks, character references decoded.
pub fn html_to_text(html: &str) -> String {
    let body = html.split_once("<body>").map_or(html, |(_, b)| b);
    let mut out = String::with_capacity(body.len());
    let mut rest = body;
    let mut pre = false;
    while let Some(start) = rest.find('<') {
        push_text(&mut out, &rest[..start], pre);
        let Some(len) = rest[start..].find('>') else {
            rest = &rest[start..];
            break;
        };
        let tag = &rest[start + 1..start + len];
        let closing = tag.starts_with('/');
        let name: String = tag
            .trim_start_matches('/')
            .chars()
            .take_while(char::is_ascii_alphanumeric)
            .collect::<String>()
            .to_ascii_lowercase();
        if name == "pre" {
            pre = !closing;
        }
        if matches!(
            name.as_str(),
            "p" | "div" | "h1" | "h2" | "h3" | "li" | "ul" | "summary" | "details" | "pre" | "br"
        ) {
            out.push('\n');
        }
        rest = &rest[start + len + 1..];
    }
    push_text(&mut out, rest, pre);
    let decoded = decode_references(&out);
    let mut text = String::with_capacity(decoded.len());
    let mut blank = true;
    for line in decoded.lines() {
        let line = line.trim_end();
        if line.trim().is_empty() {
            if !blank {
                text.push('\n');
            }
            blank = true;
        } else {
            text.push_str(line);
            text.push('\n');
            blank = false;
        }
    }
    text.trim_end().to_owned()
}

/// Text between tags: as it is inside `<pre>`, else without the indentation of
/// the HTML source at the start of each line.
fn push_text(out: &mut String, text: &str, pre: bool) {
    if pre {
        out.push_str(text);
        return;
    }
    for (i, line) in text.split('\n').enumerate() {
        if i > 0 {
            out.push('\n');
        }
        if out.is_empty() || out.ends_with('\n') {
            out.push_str(line.trim_start());
        } else {
            out.push_str(line);
        }
    }
}

/// `&#NN;`, `&#xNN;` and the five named references of XML.
fn decode_references(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let decoded = rest.find(';').filter(|&end| end <= 10).and_then(|end| {
            let name = &rest[1..end];
            let c = match name {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                _ => {
                    let number = name.strip_prefix('#')?;
                    let code = match number.strip_prefix(['x', 'X']) {
                        Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                        None => number.parse().ok()?,
                    };
                    char::from_u32(code)
                }
            }?;
            Some((c, end))
        });
        match decoded {
            Some((c, end)) => {
                out.push(c);
                rest = &rest[end + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn licence_ids_of_spdx_expressions() {
        assert_eq!(licence_ids("MIT OR Apache-2.0"), ["Apache-2.0", "MIT"]);
        assert_eq!(licence_ids("MIT/Apache-2.0"), ["Apache-2.0", "MIT"]);
        assert_eq!(licence_ids("Apache-2.0 / MIT"), ["Apache-2.0", "MIT"]);
        assert_eq!(
            licence_ids("(MIT OR Apache-2.0) AND OFL-1.1 AND Ubuntu-font-1.0"),
            ["Apache-2.0", "MIT", "OFL-1.1", "Ubuntu-font-1.0"]
        );
        assert_eq!(
            licence_ids("Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT"),
            ["Apache-2.0", "LLVM-exception", "MIT"]
        );
        assert_eq!(licence_ids("LGPL-3.0-only"), ["LGPL-3.0"]);
        assert_eq!(
            licence_ids("LGPL-3.0-or-later OR MPL-2.0"),
            ["LGPL-3.0", "MPL-2.0"]
        );
        assert_eq!(licence_ids("GPL-2.0+"), ["GPL-2.0"]);
        assert!(licence_ids("").is_empty());
    }

    #[test]
    fn cargo_tree_lines() {
        let root = Path::new("/w");
        let entry = |n: &str, v: &str, l: &str| Some((n.to_owned(), v.to_owned(), l.to_owned()));
        assert_eq!(
            parse_tree_line("anyhow v1.0.98|MIT OR Apache-2.0", root).unwrap(),
            entry("anyhow", "1.0.98", "MIT OR Apache-2.0")
        );
        assert_eq!(
            parse_tree_line(
                "serde_derive v1.0.229 (proc-macro)|MIT OR Apache-2.0 (*)",
                root
            )
            .unwrap(),
            entry("serde_derive", "1.0.229", "MIT OR Apache-2.0")
        );
        assert_eq!(
            parse_tree_line("zstd-sys v2.0.16+zstd.1.5.7|MIT/Apache-2.0", root).unwrap(),
            entry("zstd-sys", "2.0.16+zstd.1.5.7", "MIT/Apache-2.0")
        );
        assert_eq!(
            parse_tree_line(
                "tornect-core v0.1.0 (/w/crates/tornect-core)|GPL-3.0-or-later",
                root
            )
            .unwrap(),
            None
        );
        assert!(parse_tree_line("x v1.0.0 (/elsewhere/x)|MIT", root).is_err());
        assert!(parse_tree_line("x v1.0.0 (https://github.com/a/x#0123abc)|MIT", root).is_err());
    }

    #[test]
    fn manifest_fields() {
        let manifest = "[package]\nname = \"x\"\nauthors = [\n    \"Ann Example <ann@example.org>\",\n    \
                        \"The X Project\",\n]\nlicense-file = \"COPYING.txt\"\n\n[dependencies.y]\nlicense-file = \"no\"\n";
        assert_eq!(
            package_field(manifest, "license-file").as_deref(),
            Some("COPYING.txt")
        );
        assert_eq!(package_field(manifest, "license").as_deref(), None);
        assert_eq!(
            authors(manifest).as_deref(),
            Some("Ann Example, The X Project")
        );
        assert_eq!(
            authors("[package]\nauthors = [\"A <a@b>\"]\n").as_deref(),
            Some("A")
        );
        assert_eq!(authors("[package]\nname = \"x\"\n"), None);
    }

    #[test]
    fn texts_are_kept_once() {
        let mut texts = Texts::default();
        assert_eq!(texts.add("a".into(), normalise(b"MIT\r\nText  \r\n")), 1);
        assert_eq!(
            texts.add("b".into(), normalise(b"\xef\xbb\xbfMIT\nText\n\n")),
            1
        );
        assert_eq!(texts.add("c".into(), normalise(b"Other")), 2);
        assert_eq!(texts.list[0].shared, 2);
    }

    #[test]
    fn long_lines_wrap_at_words() {
        assert_eq!(wrap("aa bb cc dd", 8, "* ", "  "), "* aa bb\n  cc dd");
        assert_eq!(
            wrap("a-very-long-word x", 5, "* ", "  "),
            "* a-very-long-word\n  x"
        );
        assert_eq!(wrap("", 8, "* ", "  "), "* ");
    }

    #[test]
    fn html_notices_become_text() {
        let html = "<html><head><title>T</title></head><body>\n<h1>Notices</h1>\n<p><b>License:\
                    </b> Apache-2.0 OR MIT</p>\n<pre>Copyright &#60;x&#62; &#34;A&#34; &amp; B</pre>\
                    <p>after &#x41;</p></body></html>";
        assert_eq!(
            html_to_text(html),
            "Notices\n\nLicense: Apache-2.0 OR MIT\n\nCopyright <x> \"A\" & B\n\nafter A"
        );
        assert_eq!(
            decode_references("a &b; &#99999999; &#65"),
            "a &b; &#99999999; &#65"
        );
        // The source's indentation goes, a <pre> block's stays.
        assert_eq!(
            html_to_text(
                "<body><div>\n    <p>\n    <b>File:</b> <code>.</code>\n    </p>\n<pre>\n  \
                 indented\n</pre></div>"
            ),
            "File: .\n\n  indented"
        );
    }

    /// The rule the zips rely on: in the build graph of each platform that
    /// ships, every crate maps to at least one licence text (its own files, or
    /// canonical texts that are committed), and every bundled file exists.
    #[test]
    fn every_crate_in_both_build_graphs_maps_to_a_licence_text() {
        let root = crate::workspace_root().unwrap();
        for triple in ["x86_64-unknown-linux-gnu", "x86_64-pc-windows-gnullvm"] {
            let licences = collect(&root, triple, None).unwrap();
            assert!(
                licences.entries.len() > 300,
                "{triple}: {}",
                licences.entries.len()
            );
            for entry in &licences.entries {
                assert!(
                    !entry.texts.is_empty(),
                    "{triple}: {} has no text",
                    entry.package.name
                );
            }
            assert!(licences.entries.iter().any(|e| e.package.linked));
            for bundled in &BUNDLED {
                assert!(
                    licences
                        .entries
                        .iter()
                        .any(|e| e.package.name == bundled.krate),
                    "{triple}: {} left the graph; update BUNDLED",
                    bundled.krate
                );
            }
            assert_eq!(licences.items.len(), BUNDLED.len());
            let text = render(
                &licences,
                &Heading {
                    version: "0.0.0",
                    title: "test",
                    triple,
                    exe: "tornect",
                    lyrebird: "pt/lyrebird",
                },
            );
            let ring = text
                .lines()
                .find(|l| l.starts_with("ring "))
                .unwrap_or_else(|| panic!("{triple}: no line for ring"));
            assert!(ring.contains("  linked  Apache-2.0 AND ISC  ["), "{ring}");
        }
    }

    /// Each canonical text is the one `SOURCES.md` records, byte for byte as
    /// committed (LF line ends: a Windows checkout may turn them into CRLF, and
    /// the Windows CI job runs these tests on a tag).
    #[test]
    fn the_canonical_texts_match_their_sources_md_rows() {
        let root = crate::workspace_root().unwrap();
        let dir = root.join(CANONICAL);
        let sources = fs::read_to_string(dir.join("SOURCES.md")).unwrap();
        let mut seen = 0;
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if name == "SOURCES.md" {
                continue;
            }
            let bytes = fs::read(&path).unwrap();
            let committed = String::from_utf8(bytes).unwrap().replace("\r\n", "\n");
            let hash = crate::sha256::hex_digest(committed.as_bytes());
            let row = sources
                .lines()
                .find(|l| l.starts_with(&format!("| `{name}` |")))
                .unwrap_or_else(|| panic!("SOURCES.md has no row for {name}"));
            assert!(
                row.contains(&hash),
                "{name}: SOURCES.md does not give its sha256 {hash}"
            );
            seen += 1;
        }
        assert!(seen >= 8, "{seen} canonical texts");
    }
}
