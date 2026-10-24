//! `cargo xtask <command>` — repository automation (`docs/PLAN.md` §D.5).
//!
//! * `verify`      — plan sync, forbidden-dependency check, `cargo deny` (offline;
//!   the gate fails without it), fmt check, clippy `-D warnings` on all targets,
//!   tests, docs
//! * `lint-all`    — fmt check + clippy only
//! * `pt-fetch`    — lyrebird from the Tor Project archive, checked against
//!   `packaging/pt/SOURCES.md`, into `target/pt/<os>/`
//! * `dist`        — the release zips for Linux and Windows, with their
//!   third-party licence texts, and `SHA256SUMS`, in `target/dist/`
//!   (`docs/RELEASING.md`; installers are M8 work)
//! * `ffmpeg-fetch`— placeholder until the FFmpeg backend lands (M3)
//! * `soak`        — placeholder until the loopback demo lands (M3)

#![forbid(unsafe_code)]
#![allow(clippy::print_stdout, clippy::print_stderr)]

mod dist;
mod licences;
mod pt;
mod sha256;

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use anyhow::{Context as _, bail, ensure};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let root = workspace_root()?;
    match args.first().map(String::as_str) {
        Some("verify") => verify(&root, &args[1..]),
        Some("lint-all") => lint_all(&root),
        Some("pt-fetch") => pt::pt_fetch(&root, &args[1..]),
        Some("dist") => dist::dist(&root, &args[1..]),
        Some("ffmpeg-fetch") => {
            println!("ffmpeg-fetch: the FFmpeg backend is scheduled for M3; nothing to do yet.");
            Ok(())
        }
        Some("soak") => {
            println!("soak: the loopback demo is scheduled for M3; nothing to do yet.");
            Ok(())
        }
        _ => {
            eprintln!(
                "usage: cargo xtask <verify [--no-tests] | lint-all \
                 | pt-fetch [--linux] [--windows] [--offline] \
                 | dist [--linux] [--windows] [--allow-dirty] [--allow-old-advisory-db] \
                 | ffmpeg-fetch | soak>"
            );
            std::process::exit(2);
        }
    }
}

fn workspace_root() -> anyhow::Result<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .map(Path::to_path_buf)
        .context("xtask must live one level below the workspace root")
}

/// The variables `cargo run` gives this binary (the Cargo book, "Environment
/// variables Cargo sets for crates"). They must not reach the cargo commands the
/// gate spawns: cargo fingerprints a build script against the value in *its own*
/// environment, and `ring`'s build script asks for `rerun-if-env-changed` on
/// `CARGO_PKG_NAME` and `CARGO_PKG_VERSION_*`. With them inherited, every switch
/// between `cargo xtask` and a plain `cargo` (or the pre-commit hook) re-ran that
/// build script and rebuilt everything above it, the whole Tor stack included.
///
/// The prefix is `CARGO_PKG_`, never `CARGO_`: user settings such as
/// `CARGO_BUILD_JOBS`, `CARGO_HOME`, `CARGO_TARGET_DIR` and `CARGO_INCREMENTAL`
/// must pass through untouched.
fn set_by_cargo_run(name: &str) -> bool {
    name.starts_with("CARGO_PKG_")
        || matches!(
            name,
            "CARGO"
                | "CARGO_MANIFEST_DIR"
                | "CARGO_MANIFEST_PATH"
                | "CARGO_CRATE_NAME"
                | "CARGO_BIN_NAME"
                | "CARGO_PRIMARY_PACKAGE"
                | "CARGO_TARGET_TMPDIR"
                | "CARGO_RUSTC_CURRENT_DIR"
        )
}

fn cargo() -> Command {
    let mut cmd = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned()));
    for (name, _) in std::env::vars_os() {
        if name.to_str().is_some_and(set_by_cargo_run) {
            cmd.env_remove(&name);
        }
    }
    cmd
}

fn run(root: &Path, label: &str, mut cmd: Command) -> anyhow::Result<()> {
    let start = Instant::now();
    println!("==> {label}");
    let status = cmd
        .current_dir(root)
        .status()
        .with_context(|| format!("spawning `{label}`"))?;
    if !status.success() {
        bail!("`{label}` failed with {status}");
    }
    println!("    ok ({:.1}s)", start.elapsed().as_secs_f64());
    Ok(())
}

fn lint_all(root: &Path) -> anyhow::Result<()> {
    let mut fmt = cargo();
    fmt.args(["fmt", "--all", "--", "--check"]);
    run(root, "cargo fmt --all -- --check", fmt)?;

    let mut clippy = cargo();
    clippy.args([
        "clippy",
        "--workspace",
        "--all-targets",
        "--",
        "-D",
        "warnings",
    ]);
    run(
        root,
        "cargo clippy --workspace --all-targets -- -D warnings",
        clippy,
    )
}

/// `TORNECT_PLAN.md` (repo root) and `docs/PLAN.md` must stay byte-identical
/// (docs/notes/decisions.md M0-8); the same rule covers the UI plan
/// (`TORNECT_UI_PLAN.md` == `docs/UI_PLAN.md`, Part G of the plan).
fn plan_sync(root: &Path) -> anyhow::Result<()> {
    for (top, doc) in [
        ("TORNECT_PLAN.md", "PLAN.md"),
        ("TORNECT_UI_PLAN.md", "UI_PLAN.md"),
    ] {
        println!("==> plan sync ({top} == docs/{doc})");
        let a = std::fs::read(root.join(top)).with_context(|| format!("reading {top}"))?;
        let b = std::fs::read(root.join("docs").join(doc))
            .with_context(|| format!("reading docs/{doc}"))?;
        if a != b {
            bail!("{top} and docs/{doc} differ; copy the edited one over the other");
        }
        println!("    ok");
    }
    Ok(())
}

/// Crates that must never enter the dependency graph: a second rustls crypto
/// provider (`ring` is the only one, decision M1-3 and docs/research/quic.md
/// §1.3 — with two compiled in rustls refuses to pick one, and a dependency
/// installing its own would silently replace ours) and OpenSSL (the build must
/// need only a C compiler, docs/research/arti.md §4).
const FORBIDDEN_DEPS: [&str; 3] = ["aws-lc-rs", "aws-lc-sys", "openssl-sys"];

/// `cargo tree --workspace --target all -i <crate>` exits non-zero with "did not
/// match any packages" exactly when the crate is absent from the resolved graph
/// of **every** target: a Windows-only path to OpenSSL counts too (SLICE-A3 F8).
fn forbidden_deps(root: &Path) -> anyhow::Result<()> {
    println!(
        "==> forbidden dependencies absent ({})",
        FORBIDDEN_DEPS.join(", ")
    );
    for dep in FORBIDDEN_DEPS {
        let output = cargo()
            .args(["tree", "--workspace", "--target", "all", "-i", dep])
            .current_dir(root)
            .output()
            .with_context(|| format!("spawning `cargo tree -i {dep}`"))?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        if output.status.success() {
            bail!(
                "`{dep}` is in the dependency graph:\n{}",
                String::from_utf8_lossy(&output.stdout)
            );
        }
        if !stderr.contains("did not match any packages") {
            bail!(
                "`cargo tree -i {dep}` failed with {}:\n{stderr}",
                output.status
            );
        }
    }
    println!("    ok");
    Ok(())
}

/// The cargo-deny release the gate and dist run (docs/DEPENDENCIES.md). Another
/// release reads `deny.toml` and the advisory database with other rules, so
/// [`deny`] refuses it rather than let a check of unknown meaning pass (audit
/// finding B29).
pub(crate) const CARGO_DENY_VERSION: &str = "0.20.2";

/// The directory the pinned release's prebuilt archive unpacks into, under
/// `target/tools/`.
fn pinned_cargo_deny_dir() -> String {
    format!("cargo-deny-{CARGO_DENY_VERSION}-x86_64-unknown-linux-musl")
}

/// Every `cargo-deny` the gate may run, in the order [`choose_cargo_deny`]
/// tries them: the pinned directory of `tools` first; then its other
/// directories in name order, never in the order the file system lists them,
/// so two machines with the same directories pick the same copy; then each
/// absolute `PATH` directory in turn (a relative one would let the current
/// directory choose what runs).
fn cargo_deny_candidates(tools: &Path, path: Option<&OsStr>) -> Vec<PathBuf> {
    let bin = format!("cargo-deny{}", std::env::consts::EXE_SUFFIX);
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(tools)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .collect();
    dirs.sort();
    let on_path = path
        .into_iter()
        .flat_map(std::env::split_paths)
        .filter(|dir| dir.is_absolute());
    let mut found: Vec<PathBuf> = Vec::new();
    for candidate in std::iter::once(tools.join(pinned_cargo_deny_dir()))
        .chain(dirs)
        .chain(on_path)
        .map(|dir| dir.join(&bin))
    {
        if candidate.is_file() && !found.contains(&candidate) {
            found.push(candidate);
        }
    }
    found
}

/// `cargo-deny --version` must name [`CARGO_DENY_VERSION`]: `cargo-deny 0.20.2`,
/// optionally followed by build details. Its words, for BUILD-INFO.txt.
fn check_cargo_deny_version(bin: &Path, exit_ok: bool, stdout: &str) -> anyhow::Result<String> {
    let said = stdout.trim();
    let mut words = said.split_whitespace();
    ensure!(
        exit_ok && words.next() == Some("cargo-deny") && words.next() == Some(CARGO_DENY_VERSION),
        "{} is `{said}`, not cargo-deny {CARGO_DENY_VERSION}: the gate and dist run the pinned \
         release only, since another reads deny.toml and the advisories with other rules. {}",
        bin.display(),
        install_cargo_deny()
    );
    Ok(said.to_owned())
}

/// The first of `candidates` whose `--version`, as `version_of` reports it
/// (its success and its standard output), names [`CARGO_DENY_VERSION`], with
/// those words. A copy of another release earlier in the order is passed over,
/// so one under `target/tools/` cannot hide a pinned one on `PATH` (B29). No
/// candidate: B3-6's error. None of the pinned release: one candidate's own
/// refusal, or each candidate named with what it said.
fn choose_cargo_deny(
    candidates: &[PathBuf],
    mut version_of: impl FnMut(&Path) -> anyhow::Result<(bool, String)>,
) -> anyhow::Result<(PathBuf, String)> {
    require_cargo_deny(candidates.first().cloned())?;
    let mut refused = Vec::new();
    let mut last = None;
    for bin in candidates {
        let said = match version_of(bin) {
            Ok((exit_ok, stdout)) => match check_cargo_deny_version(bin, exit_ok, &stdout) {
                Ok(version) => return Ok((bin.clone(), version)),
                Err(e) => {
                    last = Some(e);
                    match (stdout.trim(), exit_ok) {
                        ("", true) => "says nothing".to_owned(),
                        ("", false) => "fails and says nothing".to_owned(),
                        (said, true) => format!("is `{said}`"),
                        (said, false) => format!("is `{said}` but fails"),
                    }
                }
            },
            Err(e) => {
                let said = format!("does not run ({e:#})");
                last = Some(e);
                said
            }
        };
        refused.push(format!("{} {said}", bin.display()));
    }
    match (refused.len(), last) {
        (1, Some(e)) => Err(e),
        _ => bail!(
            "none of the {} copies of cargo-deny found is cargo-deny {CARGO_DENY_VERSION}: {}. The \
             gate and dist run the first that is, in this order: target/tools/{}/, the other \
             directories of target/tools/ by name, then PATH; another release reads deny.toml \
             and the advisories with other rules. {}",
            refused.len(),
            refused.join("; "),
            pinned_cargo_deny_dir(),
            install_cargo_deny()
        ),
    }
}

fn install_cargo_deny() -> String {
    format!(
        "Install the pinned {CARGO_DENY_VERSION}: unpack the x86_64-unknown-linux-musl archive of \
         https://github.com/EmbarkStudios/cargo-deny/releases/tag/{CARGO_DENY_VERSION} into \
         target/tools/ (it makes target/tools/{}/), or `cargo install --locked \
         cargo-deny@{CARGO_DENY_VERSION}`",
        pinned_cargo_deny_dir()
    )
}

/// An executable named `bin` in an absolute `PATH` directory; a relative entry
/// would let the current directory choose what runs.
pub(crate) fn find_on_path(bin: &str) -> Option<PathBuf> {
    let bin = format!("{bin}{}", std::env::consts::EXE_SUFFIX);
    std::env::var_os("PATH").and_then(|path| search_path(&path, &bin))
}

fn search_path(path: &OsStr, file: &str) -> Option<PathBuf> {
    std::env::split_paths(path)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(file))
        .find(|p| p.is_file())
}

/// `$CARGO_HOME`, else `.cargo` in the home directory (`HOME`, or
/// `USERPROFILE` on Windows).
pub(crate) fn cargo_home() -> Option<PathBuf> {
    std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .or_else(|| std::env::var_os("USERPROFILE"))
                .map(|home| PathBuf::from(home).join(".cargo"))
        })
}

/// The advisory database `cargo deny` checks against offline: the copy of
/// RustSec's database it fetched into `$CARGO_HOME/advisory-dbs/`. The gate and
/// BUILD-INFO.txt name its commit and date, so every check says how old its
/// knowledge was (review finding E3-3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdvisoryDb {
    pub(crate) commit: String,
    /// Its commit time, seconds since the epoch.
    pub(crate) epoch: u64,
}

impl std::fmt::Display for AdvisoryDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RustSec advisory-db {}, committed {} UTC",
            self.commit,
            dist::utc(self.epoch)
        )
    }
}

/// The database cargo-deny fetches when `deny.toml` names none (its default
/// `db-urls`); a gate test holds `deny.toml` to that.
const RUSTSEC_DB_URL: &str = "https://github.com/RustSec/advisory-db";

fn advisory_db() -> anyhow::Result<AdvisoryDb> {
    let home = cargo_home().context("neither CARGO_HOME nor HOME is set")?;
    let copy = rustsec_copy(&home.join("advisory-dbs"))?;
    let out = Command::new("git")
        .arg("-C")
        .arg(&copy)
        .args(["log", "-1", "--format=%H %ct"])
        .output()
        .with_context(|| format!("running git log in {}", copy.display()))?;
    ensure!(
        out.status.success(),
        "`git log` failed in {}: {}",
        copy.display(),
        String::from_utf8_lossy(&out.stderr).trim()
    );
    parse_db_head(&String::from_utf8_lossy(&out.stdout))
        .with_context(|| format!("reading the commit of {}", copy.display()))
}

/// The one copy under `dbs` that cargo-deny checks against: with `deny.toml`
/// naming no `db-path` or `db-urls`, cargo-deny reads its copy of RustSec's
/// database there. With more than one copy, the gate and dist could not tell
/// which one it read, so they refuse (review finding L-2); a single copy of
/// another database is refused too.
fn rustsec_copy(dbs: &Path) -> anyhow::Result<PathBuf> {
    let mut copies: Vec<PathBuf> = std::fs::read_dir(dbs)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.join(".git").is_dir())
        .collect();
    copies.sort();
    match copies.as_slice() {
        [] => bail!(
            "no advisory database under {}: run `cargo deny fetch` (it needs the network)",
            dbs.display()
        ),
        [copy] => {
            let origin = git_origin(copy)?;
            ensure!(
                origin.trim_end_matches('/').trim_end_matches(".git") == RUSTSEC_DB_URL,
                "{} is a copy of {origin}, not of {RUSTSEC_DB_URL}: delete it and run `cargo \
                 deny fetch`",
                copy.display()
            );
            Ok(copy.clone())
        }
        many => bail!(
            "{} advisory database copies under {} ({}): cargo deny checks one of them and the gate \
             could not say which (review finding L-2). Delete all but RustSec's, or all of them \
             and run `cargo deny fetch`",
            many.len(),
            dbs.display(),
            many.iter()
                .filter_map(|p| p.file_name())
                .map(|n| n.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// The `origin` URL in a copy's `.git/config`.
fn git_origin(copy: &Path) -> anyhow::Result<String> {
    let config = std::fs::read_to_string(copy.join(".git").join("config"))
        .with_context(|| format!("reading {}/.git/config", copy.display()))?;
    let mut in_origin = false;
    for line in config.lines().map(str::trim) {
        if line.starts_with('[') {
            in_origin = line == "[remote \"origin\"]";
        } else if in_origin
            && let Some(url) = line.strip_prefix("url")
            && let Some(url) = url.trim_start().strip_prefix('=')
        {
            return Ok(url.trim().to_owned());
        }
    }
    bail!("{}/.git/config names no origin", copy.display())
}

/// `git log -1 --format='%H %ct'` of a database copy.
fn parse_db_head(line: &str) -> Option<AdvisoryDb> {
    let (commit, epoch) = line.trim().split_once(' ')?;
    if commit.len() != 40 || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(AdvisoryDb {
        commit: commit.to_owned(),
        epoch: epoch.parse().ok()?,
    })
}

/// An advisory that `deny.toml` tells cargo-deny to ignore, with its reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ignored {
    pub(crate) id: String,
    pub(crate) reason: String,
}

/// The `[advisories] ignore` entries of `deny.toml`, each written as
/// `{ id = "…", reason = "…" }` on one line: BUILD-INFO.txt and the release
/// notes say what the advisory check let through, and why (review note I-3).
/// An entry without a reason is an error.
pub(crate) fn ignored_advisories(deny_toml: &str) -> anyhow::Result<Vec<Ignored>> {
    let mut in_advisories = false;
    let mut in_ignore = false;
    let mut ignored = Vec::new();
    for line in deny_toml.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if in_ignore {
            if line.starts_with(']') {
                in_ignore = false;
                continue;
            }
            let id = quoted_field(line, "id")
                .with_context(|| format!("deny.toml: an ignore entry without an id: `{line}`"))?;
            let reason = quoted_field(line, "reason")
                .filter(|r| !r.trim().is_empty())
                .with_context(|| format!("deny.toml ignores {id} without a reason"))?;
            ignored.push(Ignored { id, reason });
        } else if line.starts_with('[') {
            in_advisories = line == "[advisories]";
        } else if in_advisories && line.starts_with("ignore") {
            let rest = line.split_once('[').map(|(_, r)| r.trim()).unwrap_or("");
            match rest {
                "" => in_ignore = true,
                "]" => {}
                _ => bail!("deny.toml: write each ignore entry on a line of its own"),
            }
        }
    }
    ensure!(!in_ignore, "deny.toml: the `ignore` list does not end");
    Ok(ignored)
}

/// `key = "value"` in a one-line inline table.
fn quoted_field(line: &str, key: &str) -> Option<String> {
    let pattern = format!("{key} = \"");
    let start = line.find(&pattern)? + pattern.len();
    let len = line[start..].find('"')?;
    Some(line[start..start + len].to_owned())
}

/// What a passed `cargo deny check` ran with.
pub(crate) struct Deny {
    /// `cargo-deny --version`.
    pub(crate) version: String,
    pub(crate) db: AdvisoryDb,
}

/// `cargo deny check` (advisories, bans, licenses, sources), **offline**
/// against the advisory database already on disk, so the gate needs no network
/// and says which database it used (SLICE-A3 F2, E3-3). Without `cargo-deny`
/// the gate fails (decision B3-6): a gate that could not check advisories and
/// licences is not green.
pub(crate) fn deny(root: &Path) -> anyhow::Result<Deny> {
    let candidates = cargo_deny_candidates(
        &root.join("target").join("tools"),
        std::env::var_os("PATH").as_deref(),
    );
    let chosen = choose_cargo_deny(&candidates, |bin| {
        let out = Command::new(bin)
            .arg("--version")
            .output()
            .with_context(|| format!("running {} --version", bin.display()))?;
        Ok((
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
        ))
    });
    let (bin, version) = match chosen {
        Ok(chosen) => chosen,
        Err(e) => {
            println!("==> cargo deny check (offline)");
            return Err(e);
        }
    };
    let db = match advisory_db() {
        Ok(db) => db,
        Err(e) => {
            println!("==> cargo deny check (offline)");
            return Err(e);
        }
    };
    let label = format!(
        "advisory DB {} of {} UTC",
        &db.commit[..12],
        dist::utc(db.epoch)
    );
    let mut cmd = Command::new(&bin);
    cmd.args(["--offline", "check"]);
    run(root, &format!("cargo deny check (offline; {label})"), cmd)?;
    Ok(Deny { version, db })
}

fn require_cargo_deny(found: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    found.with_context(|| {
        format!(
            "cargo-deny not found, neither under target/tools/<dir>/ nor on PATH. The gate fails \
             without it (decision B3-6): advisories, bans, licences and sources would go \
             unchecked. {}",
            install_cargo_deny()
        )
    })
}

fn verify(root: &Path, extra: &[String]) -> anyhow::Result<()> {
    let no_tests = extra.iter().any(|a| a == "--no-tests");
    plan_sync(root)?;
    forbidden_deps(root)?;
    deny(root)?;
    lint_all(root)?;
    if !no_tests {
        let mut test = cargo();
        test.args(["test", "--workspace"]);
        run(root, "cargo test --workspace", test)?;

        let mut doc = cargo();
        doc.args(["doc", "--workspace", "--no-deps"])
            .env("RUSTDOCFLAGS", "-D warnings");
        run(
            root,
            "cargo doc --workspace --no-deps (RUSTDOCFLAGS=-D warnings)",
            doc,
        )?;
    }
    println!("verify: all gates green");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `cargo test` hands this binary the same variables `cargo run` hands the gate.
    #[test]
    fn a_spawned_cargo_does_not_inherit_what_cargo_run_set() {
        let cmd = cargo();
        let removed: Vec<String> = cmd
            .get_envs()
            .filter(|(_, value)| value.is_none())
            .filter_map(|(name, _)| name.to_str().map(str::to_owned))
            .collect();
        // Nothing else goes: a filter widened to every `CARGO_` name would
        // take the developer's own settings with it, such as the
        // `CARGO_BUILD_JOBS` every build on the dev VM sets (SLICE-D R5/R8).
        for name in &removed {
            assert!(
                set_by_cargo_run(name),
                "{name} is removed, but `cargo run` did not set it"
            );
        }
        for name in [
            "CARGO_PKG_NAME",
            "CARGO_PKG_VERSION_MAJOR",
            "CARGO_MANIFEST_DIR",
        ] {
            assert!(
                std::env::var_os(name).is_some(),
                "{name} is unset: run this test through cargo"
            );
            assert!(
                removed.iter().any(|n| n == name),
                "{name} leaks into the spawned cargo"
            );
        }
    }

    /// The copy the gate tries first.
    fn find_cargo_deny_in(tools: &Path, path: Option<&OsStr>) -> Option<PathBuf> {
        cargo_deny_candidates(tools, path).into_iter().next()
    }

    /// B3-6: with no `cargo-deny` under `target/tools/` or on `PATH`, the gate
    /// step is an error, never a skip.
    #[test]
    fn a_missing_cargo_deny_fails_the_gate() {
        let dir = std::env::temp_dir().join(format!("xtask-deny-{}", std::process::id()));
        let tools = dir.join("tools");
        let bin_dir = dir.join("bin");
        std::fs::create_dir_all(tools.join("cargo-deny-0.20.2-x86_64-unknown-linux-musl")).unwrap();
        std::fs::create_dir_all(&bin_dir).unwrap();
        let path = std::env::join_paths([&bin_dir]).unwrap();

        let found = find_cargo_deny_in(&tools, Some(&path));
        assert_eq!(found, None);
        let err = require_cargo_deny(found).unwrap_err().to_string();
        assert!(err.contains("cargo-deny not found"), "{err}");
        assert!(err.contains("B3-6"), "{err}");

        // The pinned copy under target/tools/<dir>/ is found, before PATH.
        let bin = format!("cargo-deny{}", std::env::consts::EXE_SUFFIX);
        let pinned = tools
            .join("cargo-deny-0.20.2-x86_64-unknown-linux-musl")
            .join(&bin);
        std::fs::write(&pinned, b"").unwrap();
        std::fs::write(bin_dir.join(&bin), b"").unwrap();
        assert_eq!(
            require_cargo_deny(find_cargo_deny_in(&tools, Some(&path))).unwrap(),
            pinned
        );
        std::fs::remove_file(&pinned).unwrap();
        assert_eq!(
            find_cargo_deny_in(&tools, Some(&path)),
            Some(bin_dir.join(&bin))
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// B29: the pinned copy wins whatever else `target/tools/` holds, and
    /// without it the choice is by name, never by the file system's order.
    #[test]
    fn the_pinned_cargo_deny_is_chosen_first_then_by_name() {
        let dir = std::env::temp_dir().join(format!("xtask-deny-order-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let tools = dir.join("tools");
        let bin = format!("cargo-deny{}", std::env::consts::EXE_SUFFIX);
        let mut copies = Vec::new();
        for name in [
            "cargo-deny-0.21.0-x86_64-unknown-linux-musl",
            "cargo-deny-0.19.0-x86_64-unknown-linux-musl",
            "cargo-deny-0.20.2-x86_64-unknown-linux-musl",
            "a-cargo-deny-copy",
        ] {
            std::fs::create_dir_all(tools.join(name)).unwrap();
            let copy = tools.join(name).join(&bin);
            std::fs::write(&copy, b"").unwrap();
            copies.push(copy);
        }
        assert_eq!(
            pinned_cargo_deny_dir(),
            "cargo-deny-0.20.2-x86_64-unknown-linux-musl"
        );
        assert_eq!(find_cargo_deny_in(&tools, None), Some(copies[2].clone()));
        std::fs::remove_file(&copies[2]).unwrap();
        assert_eq!(find_cargo_deny_in(&tools, None), Some(copies[3].clone()));
        std::fs::remove_file(&copies[3]).unwrap();
        assert_eq!(find_cargo_deny_in(&tools, None), Some(copies[1].clone()));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// B29: a cargo-deny of another release, or one whose `--version` failed
    /// or said nothing, fails the gate.
    #[test]
    fn a_cargo_deny_of_another_release_is_refused() {
        let bin = Path::new("/opt/cargo-deny");
        assert_eq!(
            check_cargo_deny_version(bin, true, "cargo-deny 0.20.2\n").unwrap(),
            "cargo-deny 0.20.2"
        );
        assert_eq!(
            check_cargo_deny_version(bin, true, "cargo-deny 0.20.2 (1a2b3c4 2025-12-01)").unwrap(),
            "cargo-deny 0.20.2 (1a2b3c4 2025-12-01)"
        );
        for (exit_ok, said) in [
            (true, "cargo-deny 0.21.0"),
            (true, "cargo-deny 0.20.20"),
            (true, "cargo-deny 0.20"),
            (true, "cargo-deny"),
            (true, ""),
            (true, "some-other-tool 0.20.2"),
            (false, "cargo-deny 0.20.2"),
        ] {
            let err = check_cargo_deny_version(bin, exit_ok, said)
                .unwrap_err()
                .to_string();
            assert!(err.contains("not cargo-deny 0.20.2"), "{said}: {err}");
            assert!(err.contains("/opt/cargo-deny"), "{said}: {err}");
            assert!(err.contains("releases/tag/0.20.2"), "{said}: {err}");
        }
    }

    /// B29 (review): a copy of another release under `target/tools/` no longer
    /// hides a pinned one on `PATH` (the very install the refusal recommends);
    /// the pinned one, when it comes first, is the only one run; and with none
    /// pinned, every copy tried is named with what it said.
    #[test]
    fn a_cargo_deny_of_another_release_does_not_hide_the_pinned_one() {
        let dir = std::env::temp_dir().join(format!("xtask-deny-next-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let tools = dir.join("tools");
        let bin_dir = dir.join("bin");
        let bin = format!("cargo-deny{}", std::env::consts::EXE_SUFFIX);
        let newer = tools
            .join("cargo-deny-0.21.0-x86_64-unknown-linux-musl")
            .join(&bin);
        let on_path = bin_dir.join(&bin);
        for copy in [&newer, &on_path] {
            std::fs::create_dir_all(copy.parent().unwrap()).unwrap();
            std::fs::write(copy, b"").unwrap();
        }
        let path = std::env::join_paths([&bin_dir, &bin_dir]).unwrap();
        let candidates = cargo_deny_candidates(&tools, Some(&path));
        assert_eq!(candidates, [newer.clone(), on_path.clone()]);

        // 0.21.0 under target/tools/, 0.20.2 on PATH: PATH's runs.
        let mut asked = Vec::new();
        let chosen = choose_cargo_deny(&candidates, |bin| {
            asked.push(bin.to_owned());
            let said = if bin == newer.as_path() {
                "cargo-deny 0.21.0\n"
            } else {
                "cargo-deny 0.20.2\n"
            };
            Ok((true, said.to_owned()))
        })
        .unwrap();
        assert_eq!(chosen, (on_path.clone(), "cargo-deny 0.20.2".to_owned()));
        assert_eq!(asked, [newer.clone(), on_path.clone()]);

        // Neither is 0.20.2: both are named, with what each said.
        let err = choose_cargo_deny(&candidates, |bin| {
            if bin == newer.as_path() {
                Ok((true, "cargo-deny 0.21.0\n".to_owned()))
            } else {
                Err(anyhow::anyhow!(
                    "running {} --version: denied",
                    bin.display()
                ))
            }
        })
        .unwrap_err()
        .to_string();
        for part in [
            "none of the 2 copies of cargo-deny found is cargo-deny 0.20.2",
            &format!("{} is `cargo-deny 0.21.0`", newer.display()),
            &format!("{} does not run (running", on_path.display()),
            "then PATH",
            "releases/tag/0.20.2",
        ] {
            assert!(err.contains(part), "{part}: {err}");
        }
        let err = choose_cargo_deny(&candidates, |_| Ok((false, String::new())))
            .unwrap_err()
            .to_string();
        assert!(err.contains("fails and says nothing"), "{err}");

        // One copy only: its own refusal, as before.
        let err = choose_cargo_deny(std::slice::from_ref(&newer), |_| {
            Ok((true, "cargo-deny 0.21.0".to_owned()))
        })
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("is `cargo-deny 0.21.0`, not cargo-deny 0.20.2"),
            "{err}"
        );

        // The pinned copy comes first and is the only one asked.
        let pinned = tools.join(pinned_cargo_deny_dir()).join(&bin);
        std::fs::create_dir_all(pinned.parent().unwrap()).unwrap();
        std::fs::write(&pinned, b"").unwrap();
        let candidates = cargo_deny_candidates(&tools, Some(&path));
        assert_eq!(candidates, [pinned.clone(), newer.clone(), on_path.clone()]);
        let mut asked = Vec::new();
        let chosen = choose_cargo_deny(&candidates, |bin| {
            asked.push(bin.to_owned());
            Ok((true, "cargo-deny 0.20.2".to_owned()))
        })
        .unwrap();
        assert_eq!(chosen.0, pinned);
        assert_eq!(asked, [pinned]);

        // Nothing found: B3-6, before anything runs.
        let err = choose_cargo_deny(&[], |_| panic!("nothing to run"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("cargo-deny not found"), "{err}");
        assert!(err.contains("B3-6"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The pin here is the one the docs and the release notes name.
    #[test]
    fn the_cargo_deny_pin_matches_the_docs() {
        let root = workspace_root().unwrap();
        let read = |rel: &str| std::fs::read_to_string(root.join(rel)).unwrap();
        assert!(
            read("docs/DEPENDENCIES.md").contains(&format!(
                "| cargo-deny and the RustSec advisory database | {CARGO_DENY_VERSION} "
            )),
            "docs/DEPENDENCIES.md"
        );
        assert!(
            read("docs/RELEASING.md").contains(&pinned_cargo_deny_dir()),
            "docs/RELEASING.md"
        );
        assert!(
            read("packaging/release/NOTES-v0.1.0-slice.1.md")
                .contains(&format!("cargo-deny {CARGO_DENY_VERSION},")),
            "the release notes"
        );
    }

    /// Decision M1-73, Part E "Fake or altered invitations": the zipped
    /// README and the release notes name the one download location, the
    /// workspace `repository` field's releases page, which is also what an
    /// invitation names (`tornect_core::invite::DOWNLOAD_URL`).
    #[test]
    fn the_release_docs_name_the_download_location() {
        let root = workspace_root().unwrap();
        let read = |rel: &str| std::fs::read_to_string(root.join(rel)).unwrap();
        let manifest = read("Cargo.toml");
        let repository = manifest
            .lines()
            .find_map(|l| l.strip_prefix("repository = \""))
            .and_then(|l| l.strip_suffix('"'))
            .expect("the workspace repository field");
        assert_eq!(repository, "https://github.com/Mxrider007/Tornect");
        let location = format!("Download Tornect only from {repository}/releases, the one place");
        for doc in [
            "packaging/release/README-release.md",
            "packaging/release/NOTES-v0.1.0-slice.1.md",
            "README.md",
        ] {
            // Sentences wrap in the files; compare with every run of white space as one space.
            let text = read(doc).split_whitespace().collect::<Vec<_>>().join(" ");
            assert!(text.contains(&location), "{doc} lacks `{location}`");
        }
    }

    /// E3-3: the database's commit and date come from its `git log` line.
    #[test]
    fn the_advisory_database_is_named_by_commit_and_date() {
        let commit = "1931a145168d457fd79b321277b25b0e51777157";
        let db = parse_db_head(&format!("{commit} 1790198453\n")).unwrap();
        assert_eq!(
            db,
            AdvisoryDb {
                commit: commit.to_owned(),
                epoch: 1_790_198_453
            }
        );
        assert_eq!(
            db.to_string(),
            format!("RustSec advisory-db {commit}, committed 2026-09-23 21:20:53 UTC")
        );
        assert_eq!(parse_db_head("1931a14 1790198453"), None);
        assert_eq!(parse_db_head(&format!("{commit} yesterday")), None);
        assert_eq!(parse_db_head(""), None);
    }

    /// L-2: the gate names exactly the copy cargo-deny checks, and refuses
    /// when it cannot tell which one that is.
    #[test]
    fn only_a_single_rustsec_copy_is_named() {
        let dbs = std::env::temp_dir().join(format!("xtask-dbs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dbs);
        std::fs::create_dir_all(&dbs).unwrap();
        let copy = |name: &str, url: &str| {
            let git = dbs.join(name).join(".git");
            std::fs::create_dir_all(&git).unwrap();
            std::fs::write(
                git.join("config"),
                format!(
                    "[core]\n\tbare = false\n[remote \"origin\"]\n\turl = {url}\n\tfetch = x\n"
                ),
            )
            .unwrap();
        };
        let err = rustsec_copy(&dbs).unwrap_err().to_string();
        assert!(err.contains("no advisory database"), "{err}");

        copy("advisory-db-3157b0e258782691", RUSTSEC_DB_URL);
        assert_eq!(
            rustsec_copy(&dbs).unwrap(),
            dbs.join("advisory-db-3157b0e258782691")
        );

        copy(
            "advisory-db-0123456789abcdef",
            "https://example.invalid/mirror/advisory-db",
        );
        let err = rustsec_copy(&dbs).unwrap_err().to_string();
        assert!(err.contains("2 advisory database copies"), "{err}");
        assert!(err.contains("advisory-db-0123456789abcdef"), "{err}");

        std::fs::remove_dir_all(dbs.join("advisory-db-3157b0e258782691")).unwrap();
        let err = rustsec_copy(&dbs).unwrap_err().to_string();
        assert!(
            err.contains("not of https://github.com/RustSec/advisory-db"),
            "{err}"
        );
        std::fs::remove_dir_all(&dbs).unwrap();
    }

    /// L-2: cargo-deny reads the copy the gate names only while `deny.toml`
    /// leaves the database's place and URL to cargo-deny's defaults.
    #[test]
    fn deny_toml_keeps_the_default_advisory_database() {
        let deny = std::fs::read_to_string(workspace_root().unwrap().join("deny.toml")).unwrap();
        for line in deny.lines().map(str::trim) {
            assert!(
                !line.starts_with("db-path") && !line.starts_with("db-urls"),
                "deny.toml sets `{line}`: teach xtask's advisory_db() to follow it first"
            );
        }
    }

    /// I-3: the ignores are read with their reasons, and one without a reason
    /// is refused.
    #[test]
    fn deny_toml_ignores_are_read_with_their_reasons() {
        let deny = std::fs::read_to_string(workspace_root().unwrap().join("deny.toml")).unwrap();
        let ignored = ignored_advisories(&deny).unwrap();
        let ids: Vec<&str> = ignored.iter().map(|i| i.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "RUSTSEC-2023-0071",
                "RUSTSEC-2024-0436",
                "RUSTSEC-2026-0192",
                "RUSTSEC-2026-0370",
                "RUSTSEC-2026-0371",
                "RUSTSEC-2026-0372"
            ]
        );
        assert!(ignored.iter().all(|i| i.reason.len() > 20), "{ignored:?}");

        let sample = "[advisories]\nversion = 2\nignore = [\n  # why\n  { id = \"RUSTSEC-1\", \
                      reason = \"a, b; c\" },\n]\n[licenses]\nignore = [\n  \"x\",\n]\n";
        assert_eq!(
            ignored_advisories(sample).unwrap(),
            [Ignored {
                id: "RUSTSEC-1".to_owned(),
                reason: "a, b; c".to_owned()
            }]
        );
        let bare = "[advisories]\nignore = [\n  \"RUSTSEC-2\",\n]\n";
        assert!(ignored_advisories(bare).is_err());
        let no_reason = "[advisories]\nignore = [\n  { id = \"RUSTSEC-3\" },\n]\n";
        let err = ignored_advisories(no_reason).unwrap_err().to_string();
        assert!(err.contains("RUSTSEC-3 without a reason"), "{err}");
        assert!(
            ignored_advisories("[advisories]\nignore = []\n")
                .unwrap()
                .is_empty()
        );
    }

    /// Whatever the fix removes, a developer's own cargo settings must survive it.
    #[test]
    fn user_settings_still_reach_the_spawned_cargo() {
        for name in [
            "CARGO_BUILD_JOBS",
            "CARGO_HOME",
            "CARGO_TARGET_DIR",
            "CARGO_INCREMENTAL",
            "CARGO_NET_OFFLINE",
        ] {
            assert!(
                !set_by_cargo_run(name),
                "{name} is a user setting, not cargo's"
            );
        }
    }
}
