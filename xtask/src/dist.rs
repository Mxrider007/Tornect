//! `cargo xtask dist [--linux] [--windows] [--allow-dirty]`: the release zips
//! (`docs/RELEASING.md`), on a Linux x86_64 host; Windows is cross-built with
//! llvm-mingw (`docs/research/slice.md` §1).
//!
//! First the gate's `cargo deny --offline check`, whose advisory database
//! (commit and date) each BUILD-INFO.txt names (review finding E3-3).
//!
//! Per platform: lyrebird through `pt-fetch`'s checks; `cargo build --locked
//! --release` into `target/dist/cargo/`; checks on the executable (its dynamic
//! libraries or DLLs); the debug info stripped; the third-party licence file
//! (`licences.rs`); a staging tree in `target/dist/stage/`, where no file may
//! hold a path of the build machine (the workspace, `CARGO_HOME`, `RUSTUP_HOME`,
//! llvm-mingw, the home directory); then
//! `target/dist/tornect-<version>-<os>-x86_64.zip`. Last, `SHA256SUMS` over this
//! run's zips.
//!
//! Every file in a zip carries the commit's time and fixed modes, in a fixed
//! order, without owner ids, so the zip depends on its files alone.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use anyhow::{Context as _, bail, ensure};

use crate::{licences, polkit, pt, sha256};

/// Everything dist writes lives under this directory of the workspace.
const OUT: &str = "target/dist";
const README: &str = "packaging/release/README-release.md";
/// polkit's actions for the Linux re-authentication (§B.8.8): every change
/// that widens access is refused until root installs this file, so the
/// Linux zip carries it (decision M1-89).
/// Dist stages it only after [`polkit::check`] passes on the staged copy.
const POLKIT_POLICY: &str = polkit::SOURCE;
/// Where the Linux zip holds [`POLKIT_POLICY`].
const POLKIT_IN_ZIP: &str = "polkit/org.tornect.policy";

/// llvm-mingw as pinned in `docs/DEPENDENCIES.md` and `docs/research/slice.md` §1.
const LLVM_MINGW_RELEASE: &str = "20260908";
const LLVM_MINGW_DIR: &str = "llvm-mingw-20260908-ucrt-ubuntu-22.04-x86_64";
const LLVM_MINGW_ASSET_SHA256: &str =
    "2258c745e3155870c80793f3e8c80b28fbde11b9ff73c4c78783635b3440b092";
/// The first line of that release's `x86_64-w64-mingw32-clang --version`.
const LLVM_MINGW_CLANG: &str = "clang version 23.1.1 \
     (https://github.com/llvm/llvm-project.git 6dfe1677ab8dffbc6ec13d53a1e0215d75147689)";
/// Its static parts that end up inside `tornect.exe`; BUILD-INFO.txt records their hashes.
const LLVM_MINGW_LINKED: [&str; 5] = [
    "x86_64-w64-mingw32/lib/crt2.o",
    "x86_64-w64-mingw32/lib/libc++.a",
    "x86_64-w64-mingw32/lib/libmingw32.a",
    "x86_64-w64-mingw32/lib/libmingwex.a",
    "x86_64-w64-mingw32/lib/libunwind.a",
];

/// What the Linux executable may load: glibc, and the GCC runtime OpenH264's
/// C++ needs. Anything else (a system liblzma, SQLite, OpenSSL) fails the run.
const LINUX_LIBS: [&str; 8] = [
    "ld-linux-x86-64.so.2",
    "libc.so.6",
    "libdl.so.2",
    "libgcc_s.so.1",
    "libm.so.6",
    "libpthread.so.0",
    "librt.so.1",
    "libstdc++.so.6",
];

#[derive(Debug, Clone, Copy)]
struct Platform {
    /// The zip's name for it, as the tor-expert-bundle's.
    name: &'static str,
    title: &'static str,
    triple: &'static str,
    exe: &'static str,
    bundle: pt::Bundle,
}

const LINUX: Platform = Platform {
    name: "linux-x86_64",
    title: "Linux x86_64",
    triple: "x86_64-unknown-linux-gnu",
    exe: "tornect",
    bundle: pt::LINUX,
};

const WINDOWS: Platform = Platform {
    name: "windows-x86_64",
    title: "Windows x86_64",
    triple: "x86_64-pc-windows-gnullvm",
    exe: "tornect.exe",
    bundle: pt::WINDOWS,
};

impl Platform {
    fn is_windows(self) -> bool {
        self.triple.contains("windows")
    }
}

pub fn dist(root: &Path, args: &[String]) -> anyhow::Result<()> {
    let mut allow_dirty = false;
    let mut allow_old_db = false;
    let mut platforms = Vec::new();
    for arg in args {
        match arg.as_str() {
            "--linux" => platforms.push(LINUX),
            "--windows" => platforms.push(WINDOWS),
            "--allow-dirty" => allow_dirty = true,
            "--allow-old-advisory-db" => allow_old_db = true,
            other => bail!(
                "dist: unknown argument `{other}` (expected --linux, --windows, --allow-dirty or \
                 --allow-old-advisory-db)"
            ),
        }
    }
    if platforms.is_empty() {
        platforms = vec![LINUX, WINDOWS];
    }
    ensure!(
        cfg!(all(target_os = "linux", target_arch = "x86_64")),
        "dist runs on a Linux x86_64 host (it cross-builds Windows with llvm-mingw)"
    );
    let overrides = release_profile_overrides(std::env::vars_os().map(|(name, _)| name));
    ensure!(
        overrides.is_empty(),
        "{} set: they would change the release build, and BUILD-INFO.txt records Cargo.toml's \
         [profile.release] alone (audit finding B30). Unset them",
        overrides.join(", ")
    );
    // The repository's own cargo configuration reaches every build too.
    // BUILD-INFO.txt records `.cargo/config.toml` line by line, under a profile
    // line that names Cargo.toml alone, so a profile set there is refused, and
    // so is an extensionless `.cargo/config`, which cargo would read instead.
    ensure!(
        !root.join(".cargo").join("config").exists(),
        ".cargo/config exists: cargo reads it in place of .cargo/config.toml, the file \
         BUILD-INFO.txt records. Merge it into .cargo/config.toml and remove it"
    );
    let config = fs::read_to_string(root.join(".cargo").join("config.toml"))
        .context("reading .cargo/config.toml")?;
    if let Some(line) = cargo_config_profile(&config) {
        bail!(
            ".cargo/config.toml sets a profile (`{line}`): it would change the release build, \
             and BUILD-INFO.txt's profile line records Cargo.toml's [profile.release] alone \
             (audit finding B30). Move it to Cargo.toml"
        );
    }
    // The direct design §8.8 (decision M1-82): no release graph carries a
    // test-only feature; checked before anything is fetched or built.
    for platform in &platforms {
        no_test_support(root, platform.triple)?;
    }
    let version = env!("CARGO_PKG_VERSION");
    let git = Git::read(root)?;
    if git.dirty {
        ensure!(
            allow_dirty,
            "the tree has uncommitted changes: a release is built from a commit. Commit them, \
             or pass --allow-dirty for a trial build"
        );
        println!(
            "dist: WARNING: uncommitted changes; BUILD-INFO.txt says so, and these zips are no \
             release"
        );
    }
    // E3-3: the advisory check this build rests on, run here against the
    // database on disk; BUILD-INFO.txt names that database's commit and date.
    let deny = crate::deny(root)?;
    let db = deny.db.clone();
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .context("the clock is before 1970")?
        .as_secs();
    let age = db_age_days(db.epoch, now, allow_old_db)?;
    println!(
        "dist: the advisory database {} is {age} days old (dist's limit: {MAX_DB_AGE_DAYS}{})",
        &db.commit[..12],
        if age > MAX_DB_AGE_DAYS {
            "; WARNING: over it, allowed by --allow-old-advisory-db"
        } else {
            ""
        }
    );
    let deny_toml = fs::read_to_string(root.join("deny.toml")).context("reading deny.toml")?;
    let ignored = crate::ignored_advisories(&deny_toml)?;
    let checks = Checks {
        deny: &deny.version,
        db: &db,
        ignored: &ignored,
    };
    let tools = Tools::probe(root, &platforms)?;
    let out = root.join(OUT);
    fs::create_dir_all(&out).with_context(|| format!("creating {}", out.display()))?;
    let mut zips = Vec::new();
    for platform in platforms {
        zips.push(package(
            root, &out, platform, version, &git, &tools, &checks,
        )?);
    }
    let sums = write_sums(&out, &zips)?;
    println!("dist: done");
    for zip in &zips {
        let bytes = fs::metadata(zip)?.len();
        println!(
            "    {}  {bytes} bytes  sha256 {}",
            zip.display(),
            sha256::file_hex(zip)?
        );
    }
    println!("    {}", sums.display());
    println!(
        "    advisory check (for the release notes): {}",
        advisory_line(&db, git.epoch)
    );
    for i in &ignored {
        println!(
            "    ignored by deny.toml (for the release notes): {}: {}",
            i.id, i.reason
        );
    }
    Ok(())
}

/// The feature node of `tornect-net`'s test environments (`mem`: the
/// in-memory network and the loopback machine, which admit loopback
/// addresses) as `cargo tree -e features --prefix none` prints it. Only
/// dev-dependencies may enable it (the direct design §8.8, decision M1-82).
const TEST_SUPPORT: &str = "tornect-net feature \"test-support\"";

/// Refuses a release graph of `tornect` for `triple` that enables
/// `tornect-net`'s `test-support` feature: `cargo tree -p tornect --target
/// <triple> -e normal,build,features -i tornect-net` (the edges `cargo build
/// --release -p tornect` follows) must not list it (the direct design §8.8).
fn no_test_support(root: &Path, triple: &str) -> anyhow::Result<()> {
    let out = crate::cargo()
        .args([
            "tree",
            "--locked",
            "-p",
            "tornect",
            "--target",
            triple,
            "-e",
            "normal,build,features",
            "-i",
            "tornect-net",
            "--prefix",
            "none",
        ])
        .current_dir(root)
        .output()
        .context("spawning `cargo tree -i tornect-net`")?;
    ensure!(
        out.status.success(),
        "`cargo tree --target {triple} -e normal,build,features -i tornect-net` failed ({}): {}",
        out.status,
        String::from_utf8_lossy(&out.stderr).trim()
    );
    test_support_check(&String::from_utf8_lossy(&out.stdout), triple)?;
    println!("dist: {triple}: the release graph enables no test-only feature of tornect-net");
    Ok(())
}

/// [`no_test_support`]'s reading of the inverted feature tree `tree`: it
/// must be `tornect-net`'s, and no line may be [`TEST_SUPPORT`] (a repeated
/// node ends in ` (*)`).
fn test_support_check(tree: &str, triple: &str) -> anyhow::Result<()> {
    let mut lines = tree.lines().map(str::trim).filter(|l| !l.is_empty());
    ensure!(
        lines.next().is_some_and(|l| l.starts_with("tornect-net v")),
        "`cargo tree -i tornect-net` for {triple} did not print tornect-net's tree"
    );
    ensure!(
        !lines.any(|l| l.strip_suffix(" (*)").unwrap_or(l) == TEST_SUPPORT),
        "{triple}: the release graph of tornect enables tornect-net's `test-support` feature \
         (the test environments, which admit loopback addresses): only dev-dependencies may \
         enable it. `cargo tree -p tornect --target {triple} -e normal,build,features -i \
         tornect-net` shows who does"
    );
    Ok(())
}

/// The `CARGO_PROFILE_RELEASE_*` variables among `names`: cargo lets each
/// override a `[profile.release]` key, so with one set BUILD-INFO.txt's
/// profile line, read from Cargo.toml, would not describe the build.
fn release_profile_overrides(names: impl Iterator<Item = std::ffi::OsString>) -> Vec<String> {
    let mut found: Vec<String> = names
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| name.starts_with("CARGO_PROFILE_RELEASE_"))
        .collect();
    found.sort();
    found
}

/// The first line of a cargo configuration file that sets a profile: a
/// `[profile…]` table (any spacing or quoting of its first key) or, before any
/// table, a `profile…` key (dotted, or an inline table). Read by lines, as
/// xtask has no TOML parser; a `[profile` line inside a multi-line string
/// counts too, which only refuses more.
fn cargo_config_profile(config: &str) -> Option<String> {
    let first_key = |name: &str| {
        name.split('.')
            .next()
            .unwrap_or_default()
            .trim()
            .trim_matches(|c| c == '"' || c == '\'')
            .trim()
            == "profile"
    };
    let mut top_level = true;
    for line in config.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(header) = line.strip_prefix('[') {
            top_level = false;
            let name = header.trim_start_matches('[').split(']').next();
            if first_key(name.unwrap_or_default()) {
                return Some(line.to_owned());
            }
        } else if top_level && first_key(line.split('=').next().unwrap_or_default()) {
            return Some(line.to_owned());
        }
    }
    None
}

/// `[profile.release]` of the workspace's `Cargo.toml` and its sub-tables
/// (`[profile.release.package.…]`, `[profile.release.build-override]`), as
/// BUILD-INFO.txt shows them: `opt-level 3, lto "thin", …`. Read from the
/// file, so the record follows an edit there (audit finding B30).
fn release_profile(cargo_toml: &str) -> anyhow::Result<String> {
    const TABLE: &str = "[profile.release]";
    let mut prefix: Option<String> = None;
    let mut keys = Vec::new();
    for line in cargo_toml.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            prefix = if line == TABLE {
                Some(String::new())
            } else {
                line.strip_prefix("[profile.release.")
                    .and_then(|rest| rest.strip_suffix(']'))
                    .map(|sub| format!("{sub}."))
            };
            continue;
        }
        let Some(prefix) = &prefix else {
            continue;
        };
        let (key, value) = line
            .split_once('=')
            .with_context(|| format!("Cargo.toml's {TABLE}: `{line}` is not `key = value`"))?;
        ensure!(
            !value.contains('#'),
            "Cargo.toml's {TABLE}: write `{line}` without a comment after the value"
        );
        keys.push(format!("{prefix}{} {}", key.trim(), value.trim()));
    }
    ensure!(!keys.is_empty(), "Cargo.toml has no {TABLE} table");
    Ok(keys.join(", "))
}

/// What `dist` checked before building, for BUILD-INFO.txt.
struct Checks<'a> {
    /// `cargo-deny --version`.
    deny: &'a str,
    db: &'a crate::AdvisoryDb,
    /// The advisories `deny.toml` ignores, which the check let through.
    ignored: &'a [crate::Ignored],
}

/// The oldest advisory database dist builds with, in whole days (review note
/// I-2); `--allow-old-advisory-db` overrides it, which the release notes must
/// then say.
const MAX_DB_AGE_DAYS: u64 = 7;

/// The database's age at `now`, in whole days; above [`MAX_DB_AGE_DAYS`] an
/// error unless `allow_old`.
fn db_age_days(db_epoch: u64, now: u64, allow_old: bool) -> anyhow::Result<u64> {
    let days = now.saturating_sub(db_epoch) / 86_400;
    ensure!(
        days <= MAX_DB_AGE_DAYS || allow_old,
        "the advisory database is {days} days old, more than dist builds with \
         ({MAX_DB_AGE_DAYS}; review note I-2): run `cargo deny fetch` and the gate again, or pass \
         --allow-old-advisory-db and say so in the release notes"
    );
    Ok(days)
}

/// BUILD-INFO.txt's "Checked before the build" lines: the check, its
/// database, and each advisory `deny.toml` ignores with its reason (I-3).
fn check_lines(checks: &Checks<'_>, commit_epoch: u64) -> Vec<String> {
    let mut lines = vec![
        format!(
            "cargo deny    {}, `--offline check`: advisories, bans, licences and sources ok",
            checks.deny
        ),
        format!("advisories    {}", advisory_line(checks.db, commit_epoch)),
    ];
    for (n, i) in checks.ignored.iter().enumerate() {
        let label = if n == 0 { "ignored" } else { "" };
        lines.push(format!("{label:<14}{}: {}", i.id, i.reason));
    }
    lines
}

/// The advisory database and its age against the source commit, which
/// BUILD-INFO.txt can state without the build's own date (E3-3).
fn advisory_line(db: &crate::AdvisoryDb, commit_epoch: u64) -> String {
    let age = match commit_epoch.checked_sub(db.epoch) {
        Some(secs) => match secs / 86_400 {
            1 => "1 day before the source commit".to_owned(),
            days => format!("{days} days before the source commit"),
        },
        None => "after the source commit".to_owned(),
    };
    format!("{db}, {age}")
}

struct Git {
    commit: String,
    /// Commit time, seconds since the epoch: every file's time in the zips.
    epoch: u64,
    dirty: bool,
}

impl Git {
    fn read(root: &Path) -> anyhow::Result<Self> {
        let git = |args: &[&str]| capture(Command::new("git").arg("-C").arg(root).args(args));
        let commit = git(&["rev-parse", "HEAD"])?;
        let epoch = git(&["log", "-1", "--format=%ct", "HEAD"])?
            .parse()
            .context("reading the commit time")?;
        let dirty = !git(&["status", "--porcelain"])?.is_empty();
        Ok(Self {
            commit,
            epoch,
            dirty,
        })
    }
}

struct Tools {
    /// `rustc -vV`, every line.
    rustc: String,
    /// `rustc --print sysroot`: the standard library's notices are under it.
    sysroot: PathBuf,
    cargo: String,
    nasm: String,
    zip: String,
    /// `cc --version`, first line (Linux builds).
    cc: Option<String>,
    /// `strip --version`, first line (Linux builds).
    strip: Option<String>,
    mingw: Option<LlvmMingw>,
    /// The paths of this machine that no file in a zip may contain.
    local_paths: Vec<LocalPath>,
}

/// A directory of the build machine whose path no file in a zip may hold.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalPath {
    /// What the directory is, for the error.
    what: &'static str,
    /// Its path with one trailing `/`, so that `/w/` does not match `/work/`.
    needle: Vec<u8>,
    /// The home directory: a generic path such as `/root/` or `/home/runner/`
    /// can sit in a pinned third-party file, from its own build machine.
    home: bool,
}

/// The directories whose paths a zip must not carry (audit finding B28): the
/// workspace and `CARGO_HOME`, which the build's `--remap-path-prefix` hides,
/// rustup's toolchains, llvm-mingw and the home directory. Each is checked on
/// its own, so a workspace outside the home directory is checked too. `/`,
/// empty paths and repeats are left out.
fn local_paths(dirs: &[(&'static str, Option<&Path>)]) -> Vec<LocalPath> {
    let mut paths: Vec<LocalPath> = Vec::new();
    for &(what, dir) in dirs {
        let Some(dir) = dir else {
            continue;
        };
        let bytes = dir.as_os_str().as_encoded_bytes();
        let end = bytes.iter().rposition(|&b| b != b'/').map_or(0, |i| i + 1);
        if end == 0 {
            continue;
        }
        let mut needle = bytes[..end].to_vec();
        needle.push(b'/');
        if paths.iter().any(|p| p.needle == needle) {
            continue;
        }
        paths.push(LocalPath {
            what,
            needle,
            home: what == HOME_DIR,
        });
    }
    paths
}

const HOME_DIR: &str = "the home directory";

/// The first of `paths` in a file's bytes, and where. A file that `pt-fetch`
/// pinned by SHA-256 (`third_party`) is the Tor Project's, byte for byte, so
/// the generic home path is not looked for in it; every other path is.
fn find_local_path<'a>(
    bytes: &[u8],
    paths: &'a [LocalPath],
    third_party: bool,
) -> Option<(&'a LocalPath, usize)> {
    paths
        .iter()
        .filter(|p| !(third_party && p.home))
        .find_map(|p| find(bytes, &p.needle).map(|at| (p, at)))
}

struct LlvmMingw {
    root: PathBuf,
    strip: String,
    /// `(path in the toolchain, sha256)` of [`LLVM_MINGW_LINKED`].
    linked: Vec<(&'static str, String)>,
}

impl Tools {
    fn probe(root: &Path, platforms: &[Platform]) -> anyhow::Result<Self> {
        let rustc = capture(Command::new("rustc").arg("-vV").current_dir(root))?;
        let sysroot = PathBuf::from(capture(
            Command::new("rustc")
                .args(["--print", "sysroot"])
                .current_dir(root),
        )?);
        let cargo = capture(crate::cargo().arg("-V").current_dir(root))?;
        let nasm = capture(Command::new("nasm").arg("-v")).context(
            "dist needs nasm: without it `openh264-sys2` builds OpenH264 without its assembly \
             kernels, silently, so two machines would ship different code (A3-F7 (a))",
        )?;
        let zip = capture(Command::new("zip").arg("-v").env_remove("ZIPOPT"))?
            .lines()
            .find(|l| l.contains("This is Zip"))
            .unwrap_or("zip (version unknown)")
            .trim()
            .to_owned();
        capture(Command::new("unzip").arg("-v").env_remove("UNZIP"))
            .context("dist tests each zip with `unzip`")?;
        let linux = platforms.iter().any(|p| !p.is_windows());
        let first_line = |s: String| s.lines().next().unwrap_or_default().trim().to_owned();
        let (cc, strip) = if linux {
            (
                Some(first_line(capture(Command::new("cc").arg("--version"))?)),
                Some(first_line(capture(Command::new("strip").arg("--version"))?)),
            )
        } else {
            (None, None)
        };
        let mingw = if platforms.iter().any(|p| p.is_windows()) {
            Some(LlvmMingw::find()?)
        } else {
            None
        };
        let home = std::env::var_os("HOME").map(PathBuf::from);
        let cargo_home = crate::cargo_home();
        let rustup_home = std::env::var_os("RUSTUP_HOME")
            .map(PathBuf::from)
            .or_else(|| home.as_ref().map(|h| h.join(".rustup")));
        let local_paths = local_paths(&[
            ("the workspace", Some(root)),
            ("CARGO_HOME", cargo_home.as_deref()),
            ("RUSTUP_HOME", rustup_home.as_deref()),
            ("llvm-mingw", mingw.as_ref().map(|m| m.root.as_path())),
            (HOME_DIR, home.as_deref()),
        ]);
        Ok(Self {
            rustc,
            sysroot,
            cargo,
            nasm,
            zip,
            cc,
            strip,
            mingw,
            local_paths,
        })
    }
}

impl LlvmMingw {
    /// `$LLVM_MINGW`, else `~/.local/opt/<the pinned release>`; its clang must
    /// be the pinned one.
    fn find() -> anyhow::Result<Self> {
        let root = match std::env::var_os("LLVM_MINGW") {
            Some(dir) => PathBuf::from(dir),
            None => home_dir()?.join(".local").join("opt").join(LLVM_MINGW_DIR),
        };
        let clang = root.join("bin").join("x86_64-w64-mingw32-clang");
        ensure!(
            clang.is_file(),
            "llvm-mingw {LLVM_MINGW_RELEASE} not found at {}: set LLVM_MINGW to its directory \
             (docs/research/slice.md §1)",
            root.display()
        );
        let version = capture(Command::new(&clang).arg("--version"))?;
        let first = version.lines().next().unwrap_or_default().trim();
        ensure!(
            first == LLVM_MINGW_CLANG,
            "{} is `{first}`, not llvm-mingw {LLVM_MINGW_RELEASE}'s `{LLVM_MINGW_CLANG}`: \
             releases are built with the pinned toolchain (docs/DEPENDENCIES.md)",
            clang.display()
        );
        let strip = capture(
            Command::new(root.join("bin").join("x86_64-w64-mingw32-strip")).arg("--version"),
        )?
        .lines()
        .find(|l| l.contains("LLVM version"))
        .map(|l| format!("llvm-strip ({})", l.trim()))
        .unwrap_or_else(|| "llvm-strip".to_owned());
        let mut linked = Vec::new();
        for rel in LLVM_MINGW_LINKED {
            let path = root.join(rel);
            linked.push((
                rel,
                sha256::file_hex(&path).with_context(|| format!("hashing {}", path.display()))?,
            ));
        }
        Ok(Self {
            root,
            strip,
            linked,
        })
    }
}

fn home_dir() -> anyhow::Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is not set")
}

/// One platform, from the checked lyrebird to the zip.
fn package(
    root: &Path,
    out: &Path,
    platform: Platform,
    version: &str,
    git: &Git,
    tools: &Tools,
    checks: &Checks<'_>,
) -> anyhow::Result<PathBuf> {
    println!("==> dist {} ({})", platform.name, platform.triple);
    let fetched = pt::fetch(root, platform.bundle, false)?;
    let built = build(root, out, platform, tools)?;
    let facts = if platform.is_windows() {
        windows_facts(&built)?
    } else {
        linux_facts(root, &built)?
    };

    let stem = format!("tornect-{version}-{}", platform.name);
    let stage = out.join("stage");
    let dir = stage.join(&stem);
    if dir.exists() {
        fs::remove_dir_all(&dir).with_context(|| format!("removing {}", dir.display()))?;
    }
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;

    let strip_tool = strip(tools, platform, &built, &dir.join(platform.exe))?;
    pt::set_mode(&dir.join(platform.exe), 0o755)?;
    let lyrebird = lyrebird_in_zip(platform);
    let notice = notice_in_zip(platform);
    if let Some(folder) = dir.join(&lyrebird).parent() {
        fs::create_dir_all(folder).with_context(|| format!("creating {}", folder.display()))?;
    }
    place(
        &fetched.lyrebird,
        &dir.join(&lyrebird),
        0o755,
        Some(platform.bundle.member_sha256),
    )?;
    place(
        &fetched.notice,
        &dir.join(notice),
        0o644,
        Some(platform.bundle.notice_sha256),
    )?;
    place(&root.join("LICENSE"), &dir.join("LICENSE"), 0o644, None)?;
    place(
        &root.join("THIRD_PARTY_NOTICES.md"),
        &dir.join("THIRD_PARTY_NOTICES.md"),
        0o644,
        None,
    )?;
    place(
        &root.join(README),
        &dir.join("README-release.md"),
        0o644,
        None,
    )?;
    if !platform.is_windows() {
        let policy = dir.join(POLKIT_IN_ZIP);
        if let Some(parent) = policy.parent() {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        place(&root.join(POLKIT_POLICY), &policy, 0o644, None)?;
        // The copy that goes into the zip, so a trial build of a dirty tree
        // is held to the rule as well.
        let staged =
            fs::read_to_string(&policy).with_context(|| format!("reading {}", policy.display()))?;
        polkit::check(POLKIT_IN_ZIP, &staged)?;
        let said = capture(Command::new(dir.join(platform.exe)).arg("--version"))?;
        ensure!(
            said == format!("tornect {version}"),
            "the stripped executable says `{said}`, not `tornect {version}`"
        );
    }

    let licences = write_licences(root, platform, version, tools, &lyrebird, &dir)?;

    let mut files = zip_files(platform);
    let mut hashes = Vec::new();
    for file in &files {
        hashes.push((file.clone(), sha256::file_hex(&dir.join(file))?));
    }
    let info = build_info(&BuildInfo {
        root,
        version,
        platform,
        git,
        tools,
        checks,
        licences: &licences,
        flags: &flags_for_the_record(platform),
        strip: &strip_tool,
        facts: &facts,
        signature: &fetched.signature,
        hashes: &hashes,
    })?;
    fs::write(dir.join("BUILD-INFO.txt"), info)?;
    pt::set_mode(&dir.join("BUILD-INFO.txt"), 0o644)?;
    files.push("BUILD-INFO.txt".to_owned());
    files.sort();

    let stamp = SystemTime::UNIX_EPOCH + Duration::from_secs(git.epoch);
    for file in &files {
        let path = dir.join(file);
        let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        let third_party = *file == lyrebird || file == notice;
        if let Some((local, at)) = find_local_path(&bytes, &tools.local_paths, third_party) {
            bail!(
                "{} holds the path of {} ({}) at byte {at}; a zip must not carry a path of the \
                 build machine (the build's --remap-path-prefix list misses a path)",
                path.display(),
                local.what,
                String::from_utf8_lossy(&local.needle)
            );
        }
        fs::File::open(&path)
            .and_then(|f| f.set_modified(stamp))
            .with_context(|| format!("setting the time of {}", path.display()))?;
    }

    let zip = out.join(format!("{stem}.zip"));
    make_zip(&stage, &stem, &files, &zip)?;
    Ok(zip)
}

/// Where a zip holds lyrebird: on Linux `pt/lyrebird`, as since the first
/// release; on Windows `lyrebird.exe` beside `tornect.exe` (decision M1-88
/// (2), W4), where the running copy's lookup finds it first and where the
/// install's one robocopy, which copies files of the image's own folder,
/// takes it from.
fn lyrebird_in_zip(platform: Platform) -> String {
    if platform.is_windows() {
        platform.bundle.file_name().to_owned()
    } else {
        format!("pt/{}", platform.bundle.file_name())
    }
}

/// lyrebird's licence notice, beside it ([`lyrebird_in_zip`]).
fn notice_in_zip(platform: Platform) -> &'static str {
    if platform.is_windows() {
        "lyrebird.txt"
    } else {
        "pt/lyrebird.txt"
    }
}

/// The files a zip holds besides BUILD-INFO.txt, which lists their hashes.
fn zip_files(platform: Platform) -> Vec<String> {
    let mut files = vec![
        platform.exe.to_owned(),
        lyrebird_in_zip(platform),
        notice_in_zip(platform).to_owned(),
        "LICENSE".to_owned(),
        "THIRD_PARTY_NOTICES.md".to_owned(),
        licences::FILE.to_owned(),
        "README-release.md".to_owned(),
    ];
    if !platform.is_windows() {
        files.push(POLKIT_IN_ZIP.to_owned());
    }
    files
}

/// THIRD_PARTY_LICENSES.txt for the platform, into the staging tree; what it
/// covers, for BUILD-INFO.txt.
fn write_licences(
    root: &Path,
    platform: Platform,
    version: &str,
    tools: &Tools,
    lyrebird: &str,
    dir: &Path,
) -> anyhow::Result<String> {
    let rustc = tools.rustc.lines().next().unwrap_or("rustc").trim();
    let mingw = if platform.is_windows() {
        Some(
            tools
                .mingw
                .as_ref()
                .context("llvm-mingw was probed for a Windows build")?
                .root
                .as_path(),
        )
    } else {
        None
    };
    let toolchain = licences::Toolchain {
        rustc,
        sysroot: &tools.sysroot,
        mingw,
    };
    let collected = licences::collect(root, platform.triple, Some(&toolchain))?;
    let text = licences::render(
        &collected,
        &licences::Heading {
            version,
            title: platform.title,
            triple: platform.triple,
            exe: platform.exe,
            lyrebird,
        },
    );
    let path = dir.join(licences::FILE);
    fs::write(&path, &text).with_context(|| format!("writing {}", path.display()))?;
    pt::set_mode(&path, 0o644)?;
    let linked = collected
        .entries
        .iter()
        .filter(|e| e.package.linked)
        .count();
    Ok(format!(
        "{} crates ({linked} linked, {} only for the build), {} other parts, {} texts, {} bytes",
        collected.entries.len(),
        collected.entries.len() - linked,
        collected.items(),
        collected.texts(),
        text.len()
    ))
}

/// `cargo build --locked --release` for the platform, into `target/dist/cargo/`.
fn build(root: &Path, out: &Path, platform: Platform, tools: &Tools) -> anyhow::Result<PathBuf> {
    let target_dir = out.join("cargo");
    let mut cmd = crate::cargo();
    cmd.args([
        "build",
        "--locked",
        "--release",
        "--target",
        platform.triple,
        "-p",
        "tornect",
        "--target-dir",
    ])
    .arg(&target_dir)
    .arg("--config")
    .arg(rustflags_config(platform, &rustflags(root, platform)?));
    // liblzma from the source `liblzma-sys` bundles, never a system copy that
    // pkg-config happens to find (docs/notes/CONTINUATION.md, NEXT 3).
    cmd.env("LZMA_API_STATIC", "1");
    if platform.is_windows() {
        let mingw = tools
            .mingw
            .as_ref()
            .context("llvm-mingw was probed for a Windows build")?;
        let path = std::env::var_os("PATH").unwrap_or_default();
        let dirs = std::iter::once(mingw.root.join("bin")).chain(std::env::split_paths(&path));
        cmd.env("PATH", std::env::join_paths(dirs)?);
    }
    crate::run(
        root,
        &format!(
            "cargo build --locked --release --target {} -p tornect (in target/dist/cargo)",
            platform.triple
        ),
        cmd,
    )?;
    Ok(target_dir
        .join(platform.triple)
        .join("release")
        .join(platform.exe))
}

/// The flags dist adds to the target's rustflags; cargo joins them after those
/// of `.cargo/config.toml` (whose Windows flags must stay: `+crt-static`,
/// `-l:libc++.a`).
///
/// * The workspace (generated code under `OUT_DIR`) and `CARGO_HOME` (every
///   dependency's source) become `/tornect` and `/cargo` in panic locations
///   and tracing metadata: the zip names no local path, and a build elsewhere
///   produces the same bytes.
/// * On Windows, lld writes 0 instead of the link time into the PE header.
fn rustflags(root: &Path, platform: Platform) -> anyhow::Result<Vec<String>> {
    let cargo_home = match std::env::var_os("CARGO_HOME") {
        Some(dir) => PathBuf::from(dir),
        None => home_dir()?.join(".cargo"),
    };
    let mut flags = Vec::new();
    for (from, to) in [(root.to_path_buf(), "/tornect"), (cargo_home, "/cargo")] {
        let from = from
            .to_str()
            .with_context(|| format!("{} is not UTF-8", from.display()))?
            .to_owned();
        ensure!(
            !from.contains('='),
            "cannot remap a path that holds `=`: {from}"
        );
        flags.push(format!("--remap-path-prefix={from}={to}"));
    }
    if platform.is_windows() {
        flags.push("-C".to_owned());
        flags.push("link-arg=-Wl,--no-insert-timestamp".to_owned());
    }
    Ok(flags)
}

/// [`rustflags`] as BUILD-INFO.txt shows them, with the local paths named.
fn flags_for_the_record(platform: Platform) -> String {
    let mut flags =
        "--remap-path-prefix=<workspace>=/tornect --remap-path-prefix=<CARGO_HOME>=/cargo"
            .to_owned();
    if platform.is_windows() {
        flags.push_str(" -C link-arg=-Wl,--no-insert-timestamp");
    }
    flags
}

fn rustflags_config(platform: Platform, flags: &[String]) -> String {
    let items: Vec<String> = flags
        .iter()
        .map(|f| format!("\"{}\"", f.replace('\\', "\\\\").replace('"', "\\\"")))
        .collect();
    format!(
        "target.{}.rustflags = [{}]",
        platform.triple,
        items.join(", ")
    )
}

/// What the executable needs from the system, checked and recorded.
struct Facts {
    lines: Vec<String>,
}

/// The `GLIBC_` entries of a version-needs table that name no version
/// number but a glibc feature, with the glibc release that brought it. The
/// loader checks every entry, so each one sets a floor like a version does.
const GLIBC_FEATURES: [(&str, &str); 1] = [
    // `-z pack-relative-relocs` (DT_RELR), new in glibc 2.36.
    ("GLIBC_ABI_DT_RELR", "2.36"),
];

/// The newest glibc the executable's version-needs table asks for, from
/// `objdump -p`'s "Version References". The loader checks every entry of
/// that table, an entry no symbol carries included, so the table and not
/// the symbols (`objdump -T`) sets the floor. An entry of [`GLIBC_FEATURES`]
/// counts as its release; any other `GLIBC_` entry that is not a version
/// number is refused: `GLIBC_PRIVATE` ties the executable to one glibc
/// build, and a feature dist does not know has a floor it cannot state.
fn glibc_needed(headers: &str) -> anyhow::Result<String> {
    let (_, table) = headers
        .split_once("Version References:")
        .context("`objdump -p` shows no Version References")?;
    let mut newest: Option<(Vec<u32>, String)> = None;
    let mut from = "";
    for line in table.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if !line.starts_with(char::is_whitespace) {
            break;
        }
        let line = line.trim();
        if let Some(file) = line.strip_prefix("required from ") {
            from = file.trim_end_matches(':');
            continue;
        }
        let Some(name) = line.split_whitespace().last() else {
            continue;
        };
        let Some(version) = name.strip_prefix("GLIBC_") else {
            continue;
        };
        let version = GLIBC_FEATURES
            .iter()
            .find(|(feature, _)| *feature == name)
            .map_or(version, |(_, release)| *release);
        let parts: Vec<u32> = version
            .split('.')
            .map(str::parse)
            .collect::<Result<_, _>>()
            .ok()
            .with_context(|| {
                format!(
                    "the executable needs {name} from {from}, which names no glibc release: \
                     GLIBC_PRIVATE ties it to one glibc build; for a feature, find the glibc \
                     release that brought it in glibc's NEWS and add it to GLIBC_FEATURES"
                )
            })?;
        if newest.as_ref().is_none_or(|(p, _)| parts > *p) {
            newest = Some((parts, version.to_owned()));
        }
    }
    newest
        .map(|(_, v)| v)
        .context("the executable's version-needs table names no GLIBC_ version")
}

/// Every glibc floor a README states, in either of the forms the release
/// README uses: "glibc X.Y or newer" and the loader's "`GLIBC_X.Y' not
/// found", in any case and with either apostrophe. Any other "glibc"
/// followed by a number ("glibc 2.39+", "GLIBC 2.39 or later") is refused,
/// so a floor stated another way cannot go unchecked. White space must
/// already be one space per run.
fn glibc_claims(text: &str) -> anyhow::Result<Vec<String>> {
    // ASCII lowercasing keeps every byte offset.
    let lower = text.to_ascii_lowercase();
    let mut found = Vec::new();
    for (at, word) in lower.match_indices("glibc") {
        let rest = &lower[at + word.len()..];
        // Up to three characters that are neither letters nor digits.
        let sep: usize = rest
            .chars()
            .take(3)
            .take_while(|c| !c.is_alphanumeric())
            .map(char::len_utf8)
            .sum();
        let after = &rest[sep..];
        if !after.starts_with(|c: char| c.is_ascii_digit()) {
            continue;
        }
        let number: &str = &after[..after
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(after.len())];
        let version = number.trim_end_matches('.');
        let tail = &after[version.len()..];
        let recognised = match &rest[..sep] {
            " " => tail.starts_with(" or newer"),
            "_" => tail.starts_with("' not found") || tail.starts_with("\u{2019} not found"),
            _ => false,
        };
        ensure!(
            recognised,
            "`{}` states a glibc floor in a form dist does not read: write \"glibc X.Y or \
             newer\" (or the loader's \"`GLIBC_X.Y' not found\")",
            text[at..].chars().take(24).collect::<String>()
        );
        found.push(version.to_owned());
    }
    Ok(found)
}

/// The README's glibc floor must be the one the executable needs (decision
/// M1-89): it follows the build host's glibc, so a build on another host
/// would otherwise ship a README that names the wrong floor. `name` is the
/// file's path, for the message.
fn check_glibc_floor(name: &str, text: &str, needed: &str) -> anyhow::Result<()> {
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let claims = glibc_claims(&text).with_context(|| format!("reading {name}"))?;
    ensure!(
        !claims.is_empty(),
        "{name} names no glibc floor (\"glibc X.Y or newer\"): the Linux executable needs \
         GLIBC_{needed}"
    );
    for claimed in &claims {
        ensure!(
            claimed == needed,
            "{name} says glibc {claimed}, but this Linux executable needs GLIBC_{needed} (the \
             build host's glibc decides it): correct the version and the distributions named \
             with it by hand, in {name} and wherever else the floor is stated (README.md, the \
             release notes' Requirements), or build on a host with the README's glibc \
             (docs/RELEASING.md step 3)"
        );
    }
    Ok(())
}

/// [`linux_facts_from`] on the executable and the two READMEs that state
/// its glibc floor.
fn linux_facts(root: &Path, exe: &Path) -> anyhow::Result<Facts> {
    let dynamic = capture(Command::new("readelf").arg("-d").arg(exe))?;
    let symbols = capture(Command::new("objdump").arg("-T").arg(exe))?;
    let headers = capture(Command::new("objdump").arg("-p").arg(exe))?;
    let mut readmes = Vec::new();
    for name in [README, "README.md"] {
        let path = root.join(name);
        let text =
            fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        readmes.push((name, text));
    }
    linux_facts_from(
        &exe.display().to_string(),
        &dynamic,
        &symbols,
        &headers,
        &readmes,
    )
}

/// The Linux executable's libraries are all allowed ([`LINUX_LIBS`]), and
/// every README states the glibc floor its version-needs table sets
/// ([`glibc_needed`], [`check_glibc_floor`]); from `readelf -d`,
/// `objdump -T` and `objdump -p` output.
fn linux_facts_from(
    exe: &str,
    dynamic: &str,
    symbols: &str,
    headers: &str,
    readmes: &[(&str, String)],
) -> anyhow::Result<Facts> {
    let needed: Vec<&str> = dynamic
        .lines()
        .filter(|l| l.contains("(NEEDED)"))
        .filter_map(|l| l.split('[').nth(1)?.split(']').next())
        .collect();
    for lib in &needed {
        ensure!(
            LINUX_LIBS.contains(lib),
            "{exe} loads {lib}, which a release must not depend on (a system liblzma means \
             LZMA_API_STATIC did not take)"
        );
    }
    let glibc = glibc_needed(headers).with_context(|| format!("reading {exe}"))?;
    for (name, text) in readmes {
        check_glibc_floor(name, text, &glibc)?;
    }
    let newest = |prefix: &str| -> String {
        symbols
            .split(|c: char| c.is_whitespace() || c == '(' || c == ')')
            .filter_map(|w| w.strip_prefix(prefix))
            .filter_map(|v| {
                let parts: Option<Vec<u32>> = v.split('.').map(|n| n.parse().ok()).collect();
                parts.map(|p| (p, v.to_owned()))
            })
            .max()
            .map(|(_, v)| format!("{prefix}{v}"))
            .unwrap_or_else(|| "(none)".to_owned())
    };
    Ok(Facts {
        lines: vec![
            format!("dynamic libraries  {}", needed.join(", ")),
            format!(
                "newest versions    GLIBC_{glibc}, {} and {}: it needs a glibc and a libstdc++ \
                 that have them",
                newest("GLIBCXX_"),
                newest("CXXABI_")
            ),
        ],
    })
}

fn windows_facts(exe: &Path) -> anyhow::Result<Facts> {
    let headers = capture(Command::new("objdump").arg("-p").arg(exe).env("TZ", "UTC"))?;
    let dlls: Vec<&str> = headers
        .lines()
        .filter_map(|l| l.trim().strip_prefix("DLL Name: "))
        .collect();
    ensure!(!dlls.is_empty(), "no import table in {}", exe.display());
    for dll in &dlls {
        let lower = dll.to_ascii_lowercase();
        ensure!(
            !(lower.starts_with("lib")
                || lower.starts_with("vcruntime")
                || lower.starts_with("msvcp")),
            "{} imports {dll}, a toolchain DLL that Windows does not ship (the static libc++ \
             link of `.cargo/config.toml` no longer takes?)",
            exe.display()
        );
    }
    let stamp = headers
        .lines()
        .find(|l| l.starts_with("Time/Date"))
        .unwrap_or_default();
    ensure!(
        stamp.contains("1970"),
        "{}'s PE header holds a link time (`{}`), not 0",
        exe.display(),
        stamp.trim()
    );
    let mut sorted = dlls.clone();
    sorted.sort_by_key(|d| d.to_ascii_lowercase());
    Ok(Facts {
        lines: vec![
            format!(
                "imported DLLs      {}, all Windows' own: {}",
                sorted.len(),
                sorted.join(", ")
            ),
            "PE timestamp       0 (lld --no-insert-timestamp)".to_owned(),
        ],
    })
}

/// Remove the debug info (the symbols stay, so backtraces name functions).
fn strip(tools: &Tools, platform: Platform, from: &Path, to: &Path) -> anyhow::Result<String> {
    let (tool, record) = if platform.is_windows() {
        let mingw = tools.mingw.as_ref().context("llvm-mingw was probed")?;
        (
            mingw.root.join("bin").join("x86_64-w64-mingw32-strip"),
            mingw.strip.clone(),
        )
    } else {
        (
            PathBuf::from("strip"),
            tools.strip.clone().unwrap_or_else(|| "strip".to_owned()),
        )
    };
    capture(
        Command::new(tool)
            .arg("--strip-debug")
            .arg("-o")
            .arg(to)
            .arg(from),
    )?;
    Ok(record)
}

/// Copy a file into the staging tree with a fixed mode, re-checking a pinned one.
fn place(from: &Path, to: &Path, mode: u32, pin: Option<&str>) -> anyhow::Result<()> {
    fs::copy(from, to)
        .with_context(|| format!("copying {} to {}", from.display(), to.display()))?;
    pt::set_mode(to, mode)?;
    if let Some(pin) = pin {
        pt::check_file(to, pin)?;
    }
    Ok(())
}

/// `zip -X -D`: no owner ids or extra times, no directory entries; `TZ=UTC`
/// because a zip stores local time. The listing is then compared with `files`.
fn make_zip(stage: &Path, stem: &str, files: &[String], zip: &Path) -> anyhow::Result<()> {
    if zip.exists() {
        // `zip` would add to an existing archive.
        fs::remove_file(zip).with_context(|| format!("removing {}", zip.display()))?;
    }
    let names: Vec<String> = files.iter().map(|f| format!("{stem}/{f}")).collect();
    capture(
        Command::new("zip")
            .current_dir(stage)
            .env("TZ", "UTC")
            .env_remove("ZIPOPT")
            .args(["-X", "-D", "-9", "-q"])
            .arg(zip)
            .args(&names),
    )?;
    capture(
        Command::new("unzip")
            .env_remove("UNZIP")
            .arg("-tq")
            .arg(zip),
    )?;
    let listed = capture(
        Command::new("unzip")
            .env_remove("UNZIP")
            .arg("-Z1")
            .arg(zip),
    )?;
    ensure!(
        listed.lines().eq(names.iter().map(String::as_str)),
        "{} lists {listed:?}, not {names:?}",
        zip.display()
    );
    Ok(())
}

/// `SHA256SUMS` over this run's zips, in the form `sha256sum -c` reads.
fn write_sums(out: &Path, zips: &[PathBuf]) -> anyhow::Result<PathBuf> {
    let mut lines = Vec::new();
    for zip in zips {
        let name = zip
            .file_name()
            .context("a zip has a file name")?
            .to_string_lossy()
            .into_owned();
        lines.push((name, sha256::file_hex(zip)?));
    }
    lines.sort();
    let text: String = lines
        .iter()
        .map(|(name, hash)| format!("{hash}  {name}\n"))
        .collect();
    let path = out.join("SHA256SUMS");
    fs::write(&path, text).with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

struct BuildInfo<'a> {
    root: &'a Path,
    version: &'a str,
    platform: Platform,
    git: &'a Git,
    tools: &'a Tools,
    checks: &'a Checks<'a>,
    /// What THIRD_PARTY_LICENSES.txt covers.
    licences: &'a str,
    flags: &'a str,
    strip: &'a str,
    facts: &'a Facts,
    signature: &'a pt::Signature,
    hashes: &'a [(String, String)],
}

fn build_info(b: &BuildInfo<'_>) -> anyhow::Result<String> {
    let p = b.platform;
    let mut s = String::new();
    let _ = writeln!(
        s,
        "Tornect {} for {} ({})\nMade by `cargo xtask dist` (docs/RELEASING.md in the source).\n",
        b.version, p.title, p.triple
    );
    let _ = writeln!(s, "Source");
    let _ = writeln!(
        s,
        "  commit        {}{}",
        b.git.commit,
        if b.git.dirty {
            " WITH UNCOMMITTED CHANGES: not a release"
        } else {
            ""
        }
    );
    let _ = writeln!(
        s,
        "  commit time   {} ({} UTC); every file in the zip carries it\n",
        b.git.epoch,
        utc(b.git.epoch)
    );
    let _ = writeln!(s, "Checked before the build");
    for line in check_lines(b.checks, b.git.epoch) {
        let _ = writeln!(s, "  {line}");
    }
    s.push('\n');
    let _ = writeln!(s, "Build");
    let _ = writeln!(
        s,
        "  command       cargo build --locked --release --target {} -p tornect",
        p.triple
    );
    let cargo_toml = fs::read_to_string(b.root.join("Cargo.toml")).context("reading Cargo.toml")?;
    let _ = writeln!(
        s,
        "  profile       release (Cargo.toml): {}",
        release_profile(&cargo_toml)?
    );
    let _ = writeln!(s, "  rustflags     added by dist: {}", b.flags);
    let _ = writeln!(
        s,
        "  environment   LZMA_API_STATIC=1 (liblzma built from its bundled source)"
    );
    let _ = writeln!(
        s,
        "  after link    {} --strip-debug (debug info removed, symbols kept)",
        b.strip
    );
    let config = fs::read_to_string(b.root.join(".cargo").join("config.toml"))
        .context("reading .cargo/config.toml")?;
    let _ = writeln!(s, "  .cargo/config.toml, comments dropped:");
    for line in config.lines() {
        let line = line.trim();
        if !line.is_empty() && !line.starts_with('#') {
            let _ = writeln!(s, "    {line}");
        }
    }
    let _ = writeln!(s, "\nToolchain");
    let mut rustc = b.tools.rustc.lines().map(str::trim);
    let _ = writeln!(s, "  rustc         {}", rustc.next().unwrap_or_default());
    for line in rustc.filter(|l| !l.starts_with("binary:") && !l.starts_with("release:")) {
        let _ = writeln!(s, "                {line}");
    }
    let _ = writeln!(s, "  cargo         {}", b.tools.cargo.trim());
    if p.is_windows() {
        let mingw = b.tools.mingw.as_ref().context("llvm-mingw was probed")?;
        let _ = writeln!(
            s,
            "  C/C++, link   llvm-mingw {LLVM_MINGW_RELEASE} (UCRT, ubuntu-22.04-x86_64 build): \
             {LLVM_MINGW_CLANG}"
        );
        let _ = writeln!(
            s,
            "                release asset sha256 {LLVM_MINGW_ASSET_SHA256} (the pin in \
             docs/DEPENDENCIES.md)"
        );
        let _ = writeln!(s, "                linked into the executable:");
        for (rel, hash) in &mingw.linked {
            let _ = writeln!(s, "                  {hash}  {rel}");
        }
    } else {
        let _ = writeln!(
            s,
            "  C/C++         {}",
            b.tools.cc.as_deref().unwrap_or("cc")
        );
    }
    let _ = writeln!(s, "  nasm          {}", b.tools.nasm.trim());
    let _ = writeln!(s, "  zip           {}\n", b.tools.zip);
    let _ = writeln!(s, "Executable");
    for line in &b.facts.lines {
        let _ = writeln!(s, "  {line}");
    }
    let _ = writeln!(s, "\nLicences");
    let _ = writeln!(s, "  {}  {}", licences::FILE, b.licences);
    let _ = writeln!(s, "\nlyrebird ({})", lyrebird_in_zip(p));
    let _ = writeln!(
        s,
        "  source        lyrebird {} from Tor Browser {}'s {} (sha256 {})",
        pt::LYREBIRD_VERSION,
        pt::TOR_BROWSER,
        p.bundle.tarball(),
        p.bundle.tarball_sha256
    );
    let _ = writeln!(s, "  signature     {}", b.signature);
    let _ = writeln!(s, "\nFiles (sha256)");
    for (file, hash) in b.hashes {
        let _ = writeln!(s, "  {hash}  {file}");
    }
    Ok(s)
}

/// `YYYY-MM-DD HH:MM:SS` for seconds since the epoch (UTC).
pub(crate) fn utc(epoch: u64) -> String {
    let days = epoch / 86_400;
    let secs = epoch % 86_400;
    // Howard Hinnant's civil_from_days, for days since 1970-01-01.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}",
        secs / 3_600,
        secs % 3_600 / 60,
        secs % 60
    )
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Run a command to completion; its trimmed stdout, or an error with its stderr.
fn capture(cmd: &mut Command) -> anyhow::Result<String> {
    let program = cmd.get_program().to_string_lossy().into_owned();
    let out = cmd
        .output()
        .with_context(|| format!("running `{program}`"))?;
    ensure!(
        out.status.success(),
        "`{program}` failed ({}): {}",
        out.status,
        String::from_utf8_lossy(&out.stderr).trim()
    );
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The inverted feature tree of the release graph as `cargo tree` printed
    /// it on 2026-10-27 (`-e normal,build,features -i tornect-net --prefix
    /// none`, `x86_64-unknown-linux-gnu`; the paths shortened).
    const RELEASE_TREE: &str = "tornect-net v0.1.0 (/w/crates/tornect-net)
tornect-net feature \"default\"
tornect v0.1.0 (/w/apps/tornect)
tornect feature \"default\" (command-line)
tornect-session v0.1.0 (/w/crates/tornect-session)
tornect-session feature \"default\"
tornect v0.1.0 (/w/apps/tornect) (*)
";

    /// The direct design §8.8 and §12.1: the dist feature check passes the
    /// release graph and refuses a fixture graph in which a normal
    /// dependency enables `tornect-net`'s `test-support` (as a first and as
    /// a repeated node), and a tree that is not tornect-net's; a feature
    /// that only starts with the same name is not it.
    #[test]
    fn the_feature_check_refuses_a_graph_with_test_support() {
        let triple = "x86_64-unknown-linux-gnu";
        test_support_check(RELEASE_TREE, triple).unwrap();
        let enabled = format!(
            "{RELEASE_TREE}tornect-net feature \"test-support\"\ntornect v0.1.0 \
             (/w/apps/tornect) (*)\n"
        );
        let err = test_support_check(&enabled, triple)
            .unwrap_err()
            .to_string();
        assert!(err.contains(triple), "{err}");
        assert!(err.contains("`test-support`"), "{err}");
        let repeated = format!("{RELEASE_TREE}tornect-net feature \"test-support\" (*)\n");
        assert!(test_support_check(&repeated, triple).is_err());
        let indented = format!("{RELEASE_TREE}    tornect-net feature \"test-support\"\n");
        assert!(test_support_check(&indented, triple).is_err());
        let other = format!("{RELEASE_TREE}tornect-net feature \"test-support-docs\"\n");
        test_support_check(&other, triple).unwrap();
        assert!(test_support_check("", triple).is_err());
        assert!(test_support_check("tornect v0.1.0 (/w/apps/tornect)\n", triple).is_err());
    }

    /// The check on the workspace as it is: neither graph that ships
    /// enables the test environments (the app and the session crate enable
    /// them for their own tests only).
    #[test]
    fn neither_release_graph_enables_test_support() {
        let root = crate::workspace_root().unwrap();
        for triple in [LINUX.triple, WINDOWS.triple] {
            no_test_support(&root, triple).unwrap();
        }
    }

    #[test]
    fn utc_dates() {
        assert_eq!(utc(0), "1970-01-01 00:00:00");
        assert_eq!(utc(951_782_400), "2000-02-29 00:00:00");
        assert_eq!(utc(1_790_193_600), "2026-09-23 20:00:00");
        assert_eq!(utc(4_107_542_399), "2100-02-28 23:59:59");
    }

    /// E3-3: BUILD-INFO.txt says which advisory database the check used and
    /// how much older than the source it is.
    #[test]
    fn the_advisory_line_names_the_database_and_its_age() {
        let db = crate::AdvisoryDb {
            commit: "1931a145168d457fd79b321277b25b0e51777157".to_owned(),
            epoch: 1_790_198_453,
        };
        let line = advisory_line(&db, 1_790_198_453 + 3 * 86_400 + 5);
        assert_eq!(
            line,
            "RustSec advisory-db 1931a145168d457fd79b321277b25b0e51777157, committed \
             2026-09-23 21:20:53 UTC, 3 days before the source commit"
        );
        assert!(
            advisory_line(&db, db.epoch + 86_400).ends_with(", 1 day before the source commit")
        );
        assert!(advisory_line(&db, db.epoch).ends_with(", 0 days before the source commit"));
        assert!(advisory_line(&db, db.epoch - 1).ends_with(", after the source commit"));
    }

    /// I-2: dist refuses an advisory database more than a week old unless told
    /// otherwise, and a clock behind the database counts as age 0.
    #[test]
    fn an_old_advisory_database_is_refused_unless_allowed() {
        let db = 1_790_198_453;
        let day = 86_400;
        assert_eq!(db_age_days(db, db + 3 * day, false).unwrap(), 3);
        assert_eq!(db_age_days(db, db + 7 * day + day - 1, false).unwrap(), 7);
        let err = db_age_days(db, db + 8 * day, false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("8 days old"), "{err}");
        assert!(err.contains("--allow-old-advisory-db"), "{err}");
        assert_eq!(db_age_days(db, db + 40 * day, true).unwrap(), 40);
        assert_eq!(db_age_days(db, db - day, false).unwrap(), 0);
    }

    /// I-3: BUILD-INFO.txt names each advisory that deny.toml ignores, with
    /// its reason.
    #[test]
    fn build_info_names_every_ignored_advisory_with_its_reason() {
        let root = crate::workspace_root().unwrap();
        let deny = fs::read_to_string(root.join("deny.toml")).unwrap();
        let ignored = crate::ignored_advisories(&deny).unwrap();
        let db = crate::AdvisoryDb {
            commit: "1931a145168d457fd79b321277b25b0e51777157".to_owned(),
            epoch: 1_790_198_453,
        };
        let checks = Checks {
            deny: "cargo-deny 0.20.2",
            db: &db,
            ignored: &ignored,
        };
        let lines = check_lines(&checks, db.epoch).join("\n");
        for i in &ignored {
            assert!(
                lines.contains(&format!("{}: {}", i.id, i.reason)),
                "BUILD-INFO.txt lacks {}:\n{lines}",
                i.id
            );
        }
        assert!(
            lines.contains("\nignored       RUSTSEC-2023-0071: "),
            "{lines}"
        );
    }

    /// B30: the profile line is read from Cargo.toml (today's file gives the
    /// line BUILD-INFO.txt carried before), follows an edit there, and no
    /// profile beside `release` suggests that dist builds with another.
    #[test]
    fn the_profile_line_is_read_from_cargo_toml() {
        let root = crate::workspace_root().unwrap();
        let cargo_toml = fs::read_to_string(root.join("Cargo.toml")).unwrap();
        assert_eq!(
            release_profile(&cargo_toml).unwrap(),
            "opt-level 3, lto \"thin\", codegen-units 1, debug \"line-tables-only\""
        );
        assert!(
            !cargo_toml.contains("[profile.dist"),
            "dist builds with --release: a [profile.dist] would go unused"
        );

        let edited = "[profile.dev]\nopt-level = 1\n\n[profile.release]\n# fat now\nlto = \"fat\"\n\
                      strip = \"symbols\"\n\n[profile.release.package.\"*\"]\nopt-level = 2\n\n\
                      [workspace.lints.rust]\nunsafe_code = \"warn\"\n";
        assert_eq!(
            release_profile(edited).unwrap(),
            "lto \"fat\", strip \"symbols\", package.\"*\".opt-level 2"
        );
        assert!(release_profile("[profile.dev]\nopt-level = 1\n").is_err());
        assert!(release_profile("[profile.release]\nlto = \"fat\" # comment\n").is_err());
    }

    /// B30 (review): the repository's `.cargo/config.toml` reaches the release
    /// build as well, so a profile set there stops dist; today's file sets none.
    #[test]
    fn a_profile_in_the_repositorys_cargo_config_is_found() {
        let root = crate::workspace_root().unwrap();
        let config = fs::read_to_string(root.join(".cargo").join("config.toml")).unwrap();
        assert_eq!(cargo_config_profile(&config), None);
        assert!(
            !root.join(".cargo").join("config").exists(),
            "cargo would read .cargo/config in place of .cargo/config.toml"
        );

        let appended = format!("{config}\n[profile.release.build-override]\nopt-level = 0\n");
        for (edited, line) in [
            ("[profile.release]\nlto = \"fat\"\n", "[profile.release]"),
            (
                "[env]\nA = \"1\"\n\n  [ profile . release ]  \n",
                "[ profile . release ]",
            ),
            (
                "[\"profile\".release.package.foo]\nopt-level = 0\n",
                "[\"profile\".release.package.foo]",
            ),
            ("[profile]\nrelease = { lto = \"fat\" }\n", "[profile]"),
            (
                "profile.release.lto = \"fat\"\n[alias]\nx = \"run\"\n",
                "profile.release.lto = \"fat\"",
            ),
            (
                "# top\n'profile' = { release = { strip = true } }\n",
                "'profile' = { release = { strip = true } }",
            ),
            (appended.as_str(), "[profile.release.build-override]"),
        ] {
            assert_eq!(
                cargo_config_profile(edited).as_deref(),
                Some(line),
                "{edited}"
            );
        }
        for clean in [
            "# [profile.release]\n[alias]\nxtask = \"run\"\n",
            "[env]\nprofile = \"an environment variable\"\n",
            "[target.x86_64-pc-windows-gnullvm]\nrustflags = [\"-C\", \"profile=x\"]\n",
            "[profiles]\nx = 1\n",
        ] {
            assert_eq!(cargo_config_profile(clean), None, "{clean}");
        }
    }

    /// B30: a `CARGO_PROFILE_RELEASE_*` variable changes the build behind the
    /// profile line's back, so dist names it and stops.
    #[test]
    fn release_profile_variables_are_found() {
        let names = [
            "CARGO_BUILD_JOBS",
            "CARGO_PROFILE_RELEASE_LTO",
            "CARGO_PROFILE_DEV_OPT_LEVEL",
            "CARGO_PROFILE_RELEASE_BUILD_OVERRIDE_OPT_LEVEL",
        ]
        .map(std::ffi::OsString::from);
        assert_eq!(
            release_profile_overrides(names.into_iter()),
            [
                "CARGO_PROFILE_RELEASE_BUILD_OVERRIDE_OPT_LEVEL",
                "CARGO_PROFILE_RELEASE_LTO"
            ]
        );
    }

    /// cargo joins these after `.cargo/config.toml`'s; a `RUSTFLAGS` variable
    /// would replace those instead and drop `+crt-static`.
    #[test]
    fn the_windows_flags_are_one_toml_array_for_the_target() {
        let flags = vec![
            "--remap-path-prefix=/w=/tornect".to_owned(),
            "-C".to_owned(),
            "link-arg=-Wl,--no-insert-timestamp".to_owned(),
        ];
        assert_eq!(
            rustflags_config(WINDOWS, &flags),
            "target.x86_64-pc-windows-gnullvm.rustflags = [\"--remap-path-prefix=/w=/tornect\", \
             \"-C\", \"link-arg=-Wl,--no-insert-timestamp\"]"
        );
        let root = crate::workspace_root().unwrap();
        let linux = rustflags(&root, LINUX).unwrap();
        assert_eq!(linux.len(), 2);
        assert!(linux[0].ends_with("=/tornect") && linux[1].ends_with("=/cargo"));
        assert!(rustflags(&root, WINDOWS).unwrap().ends_with(&[
            "-C".to_owned(),
            "link-arg=-Wl,--no-insert-timestamp".to_owned()
        ]));
    }

    /// The toolchain pin here is the one the docs record.
    #[test]
    fn the_llvm_mingw_pin_matches_the_docs() {
        let root = crate::workspace_root().unwrap();
        for doc in ["docs/DEPENDENCIES.md", "docs/research/slice.md"] {
            let text = fs::read_to_string(root.join(doc)).unwrap();
            assert!(text.contains(LLVM_MINGW_ASSET_SHA256), "{doc}");
            assert!(text.contains(LLVM_MINGW_RELEASE), "{doc}");
            assert!(text.contains("clang 23.1.1"), "{doc}");
        }
        assert!(LLVM_MINGW_DIR.contains(LLVM_MINGW_RELEASE));
    }

    #[test]
    fn a_home_path_is_found_anywhere_in_a_file() {
        assert_eq!(find(b"abc/home/u/x", b"/home/u/"), Some(3));
        assert_eq!(find(b"/home/runner/x", b"/home/u/"), None);
        assert_eq!(find(b"abc", b""), None);
    }

    /// B28: with the workspace outside the home directory (here `/w` and
    /// `/root`), a path under the workspace is still refused; the generic
    /// home path is not looked for in the pinned lyrebird files.
    #[test]
    fn every_local_path_is_looked_for_not_only_home() {
        let paths = local_paths(&[
            ("the workspace", Some(Path::new("/w"))),
            ("CARGO_HOME", Some(Path::new("/root/.cargo/"))),
            ("RUSTUP_HOME", None),
            ("llvm-mingw", Some(Path::new("/"))),
            (HOME_DIR, Some(Path::new("/root"))),
            ("again", Some(Path::new("/w/"))),
        ]);
        let needles: Vec<&[u8]> = paths.iter().map(|p| p.needle.as_slice()).collect();
        assert_eq!(needles, [&b"/w/"[..], b"/root/.cargo/", b"/root/"]);

        let what = |bytes: &[u8], third_party: bool| {
            find_local_path(bytes, &paths, third_party).map(|(p, at)| (p.what, at))
        };
        // A C `__FILE__` from OUT_DIR under the workspace, which `$HOME` alone missed.
        let out_dir = b"..assert /w/target/dist/cargo/release/build/x/out/a.c..";
        assert_eq!(what(out_dir, false), Some(("the workspace", 9)));
        assert_eq!(what(out_dir, true), Some(("the workspace", 9)));
        assert_eq!(what(b"/work/x /wx", false), None);
        // The home path: refused in Tornect's own files, not in the pinned ones.
        assert_eq!(what(b"go: /root/go/pkg", false), Some((HOME_DIR, 4)));
        assert_eq!(what(b"go: /root/go/pkg", true), None);
        assert_eq!(
            what(b"/root/.cargo/registry", true),
            Some(("CARGO_HOME", 0))
        );
        assert_eq!(what(b"nothing local", false), None);
    }

    /// RELEASING.md item 7: each zip carries the generated licence texts
    /// beside Tornect's own licence and notices.
    #[test]
    fn each_zip_carries_the_third_party_licences() {
        for platform in [LINUX, WINDOWS] {
            let files = zip_files(platform);
            for needed in [
                licences::FILE,
                "LICENSE",
                "THIRD_PARTY_NOTICES.md",
                notice_in_zip(platform),
            ] {
                assert!(
                    files.iter().any(|f| f == needed),
                    "{}: {needed} is not in the zip",
                    platform.name
                );
            }
        }
    }

    /// Decision M1-88 (2), W4: the Windows zip holds `lyrebird.exe` and its
    /// notice beside `tornect.exe`, where the running copy's lookup finds it
    /// first and the install's one robocopy (which names `tornect.exe` and
    /// `lyrebird.exe` of the image's own folder) takes it from, and nothing
    /// under `pt\`; the Linux zip keeps `pt/lyrebird`, where the Linux
    /// install reads it as well.
    #[test]
    fn the_windows_zip_puts_lyrebird_beside_tornect_exe() {
        let windows = zip_files(WINDOWS);
        for needed in ["tornect.exe", "lyrebird.exe", "lyrebird.txt"] {
            assert!(windows.iter().any(|f| f == needed), "{needed}: {windows:?}");
        }
        assert!(!windows.iter().any(|f| f.starts_with("pt/")), "{windows:?}");
        let linux = zip_files(LINUX);
        for needed in ["tornect", "pt/lyrebird", "pt/lyrebird.txt"] {
            assert!(linux.iter().any(|f| f == needed), "{needed}: {linux:?}");
        }
        // The install's robocopy names this very file.
        let root = crate::workspace_root().unwrap();
        let install =
            fs::read_to_string(root.join("crates/tornect-platform/src/install.rs")).unwrap();
        assert!(
            install.contains(&format!(
                "pub const WINDOWS_LYREBIRD: &str = \"{}\";",
                lyrebird_in_zip(WINDOWS)
            )),
            "the Windows install copies another name than the zip's lyrebird"
        );
    }

    /// Decision M1-89: the Linux zip carries polkit's policy file, without
    /// which every change that widens access is refused there; the Windows
    /// zip, whose re-authentication is Windows' own prompt, does not.
    #[test]
    fn the_linux_zip_alone_carries_the_polkit_policy() {
        assert!(
            zip_files(LINUX).iter().any(|f| f == POLKIT_IN_ZIP),
            "the Linux zip lacks {POLKIT_IN_ZIP}"
        );
        assert!(
            !zip_files(WINDOWS).iter().any(|f| f.contains("polkit")),
            "the Windows zip carries a polkit file"
        );
        let root = crate::workspace_root().unwrap();
        let policy = fs::read_to_string(root.join(POLKIT_POLICY)).unwrap();
        assert!(
            policy.contains("<action id=\"org.tornect.autostart\">"),
            "{POLKIT_POLICY} is not Tornect's policy"
        );
        assert!(POLKIT_POLICY.ends_with(POLKIT_IN_ZIP));
    }

    #[test]
    fn glibc_claims_reads_both_forms() {
        let text = "with **glibc 2.43 or newer**: here it stops with \"version `GLIBC_2.43' not \
                    found\"; the glibc and the GCC runtime";
        assert_eq!(glibc_claims(text).unwrap(), ["2.43", "2.43"]);
        assert!(glibc_claims("no floor named here").unwrap().is_empty());
        // In any case, and with either apostrophe.
        assert_eq!(
            glibc_claims("GLIBC 2.43 or newer; `glibc_2.43\u{2019} not found").unwrap(),
            ["2.43", "2.43"]
        );
    }

    /// The documentation pass's security review: a floor stated in a form
    /// dist does not read is refused, not passed over, so a stale floor
    /// cannot sit unchecked beside a correct one. (Until this change the
    /// test above passed "glibc 2.39." and "GLIBC_2.2.5 is old" over; that
    /// leniency is what changed.)
    #[test]
    fn a_glibc_floor_in_another_form_is_refused() {
        for text in [
            "glibc 2.39+",
            "GLIBC 2.39 or later",
            "glibc 2.39.",
            "GLIBC_2.2.5 is old",
            "glibc-2.39 or newer",
            "needs glibc **2.39** or newer",
            "glibc2.39 or newer",
        ] {
            let refused = glibc_claims(text).expect_err(text).to_string();
            assert!(refused.contains("form dist does not read"), "{refused}");
        }
        let both = "x86_64 Linux with glibc 2.43 or newer (glibc 2.39+ works too)";
        assert!(check_glibc_floor("R", both, "2.43").is_err());
    }

    /// `objdump -p` of a Linux executable, as the build hosts print it.
    const OBJDUMP_P: &str = "\nt:     file format elf64-x86-64\n\nDynamic Section:\n  NEEDED  \
                             libc.so.6\n\nVersion References:\n  required from libgcc_s.so.1:\n    \
                             0x0b792650 0x00 05 GCC_3.0\n  required from libc.so.6:\n    \
                             0x09691a75 0x00 03 GLIBC_2.2.5\n    0x069691b9 0x00 11 GLIBC_2.39\n    \
                             0x069691b4 0x00 02 GLIBC_2.34\n  required from \
                             ld-linux-x86-64.so.2:\n    0x0d696913 0x00 06 GLIBC_2.3\n\n";

    /// The documentation pass's security review: the floor is read from the
    /// version-needs table, which the loader checks entry by entry, so an
    /// entry no symbol carries counts: `GLIBC_ABI_DT_RELR` as glibc 2.36,
    /// and `GLIBC_PRIVATE` or a feature dist does not know is refused.
    #[test]
    fn the_glibc_floor_is_read_from_the_version_needs_table() {
        assert_eq!(glibc_needed(OBJDUMP_P).unwrap(), "2.39");
        let older = OBJDUMP_P.replace("GLIBC_2.39", "GLIBC_2.35");
        assert_eq!(glibc_needed(&older).unwrap(), "2.35");
        let entry = |name: &str| {
            older.replace(
                "06 GLIBC_2.3\n",
                &format!("06 GLIBC_2.3\n    0x0fd4b2d3 0x00 07 {name}\n"),
            )
        };
        assert_eq!(glibc_needed(&entry("GLIBC_ABI_DT_RELR")).unwrap(), "2.36");
        for refused in ["GLIBC_PRIVATE", "GLIBC_ABI_SOMETHING_NEW"] {
            let message = format!("{:#}", glibc_needed(&entry(refused)).unwrap_err());
            assert!(
                message.contains(refused) && message.contains("ld-linux-x86-64.so.2"),
                "{message}"
            );
        }
        assert!(glibc_needed("Dynamic Section:\n").is_err());
        assert!(
            glibc_needed(
                "Version References:\n  required from libgcc_s.so.1:\n    0x0 0x00 05 GCC_3.0\n"
            )
            .is_err()
        );
    }

    /// The reader takes the table as this host's `objdump -p` prints it:
    /// this test executable's own, whose floor is at least the newest
    /// `GLIBC_` version its symbols name.
    #[cfg(target_os = "linux")]
    #[test]
    fn this_hosts_objdump_output_is_read() {
        let exe = std::env::current_exe().unwrap();
        let headers = capture(Command::new("objdump").arg("-p").arg(&exe)).unwrap();
        let symbols = capture(Command::new("objdump").arg("-T").arg(&exe)).unwrap();
        let parts = |v: &str| -> Vec<u32> { v.split('.').map(|n| n.parse().unwrap()).collect() };
        let table = parts(&glibc_needed(&headers).unwrap());
        let newest_symbol = symbols
            .split(|c: char| c.is_whitespace() || c == '(' || c == ')')
            .filter_map(|w| w.strip_prefix("GLIBC_"))
            .filter(|v| v.starts_with(|c: char| c.is_ascii_digit()))
            .map(parts)
            .max()
            .unwrap();
        assert!(table >= newest_symbol, "{table:?} < {newest_symbol:?}");
    }

    /// The README check is part of reading the Linux executable's facts,
    /// which dist cannot do without: a README whose floor is not the
    /// table's stops it, as does a library a release may not load.
    #[test]
    fn the_linux_facts_hold_the_readmes_to_the_table() {
        let dynamic = " 0x0000000000000001 (NEEDED)  Shared library: [libc.so.6]\n";
        let symbols =
            "0000000000000000  DF *UND*  0000000000000000 (GLIBC_2.34) __libc_start_main\n";
        let readme = |text: &str| vec![("R", text.to_owned())];
        let facts = linux_facts_from(
            "t",
            dynamic,
            symbols,
            OBJDUMP_P,
            &readme("glibc 2.39 or newer"),
        )
        .unwrap();
        assert!(
            facts.lines.iter().any(|l| l.contains("GLIBC_2.39,")),
            "{:?}",
            facts.lines
        );
        // The symbols name 2.34 at most; the table's 2.39 decides.
        let stale = linux_facts_from(
            "t",
            dynamic,
            symbols,
            OBJDUMP_P,
            &readme("glibc 2.34 or newer"),
        )
        .err()
        .expect("a README with the symbols' floor passed")
        .to_string();
        assert!(stale.contains("R says glibc 2.34"), "{stale}");
        assert!(linux_facts_from("t", dynamic, symbols, OBJDUMP_P, &readme("no floor")).is_err());
        let lzma =
            format!("{dynamic} 0x0000000000000001 (NEEDED)  Shared library: [liblzma.so.5]\n");
        assert!(
            linux_facts_from(
                "t",
                &lzma,
                symbols,
                OBJDUMP_P,
                &readme("glibc 2.39 or newer")
            )
            .is_err()
        );
    }

    /// Decision M1-89: dist refuses a README whose glibc floor is not the
    /// one the executable needs, and one that names none.
    #[test]
    fn a_readme_with_another_glibc_floor_is_refused() {
        let readme = "x86_64 Linux with **glibc 2.43 or newer**: there this build stops at once \
                      with\n\"version `GLIBC_2.43' not found\"";
        check_glibc_floor("R", readme, "2.43").unwrap();
        let refused = check_glibc_floor("R", readme, "2.39")
            .unwrap_err()
            .to_string();
        assert!(refused.contains("R says glibc 2.43"), "{refused}");
        assert!(refused.contains("needs GLIBC_2.39"), "{refused}");
        let half = "glibc 2.39 or newer; \"version `GLIBC_2.43' not found\"";
        assert!(check_glibc_floor("R", half, "2.39").is_err());
        assert!(check_glibc_floor("R", "no floor", "2.39").is_err());
    }

    /// The committed READMEs that dist checks state one glibc floor between
    /// them, in every place they state it.
    #[test]
    fn the_readmes_name_one_glibc_floor() {
        let root = crate::workspace_root().unwrap();
        let mut floors = Vec::new();
        for name in [README, "README.md"] {
            let text = fs::read_to_string(root.join(name)).unwrap();
            let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
            let claims = glibc_claims(&text).unwrap();
            assert!(!claims.is_empty(), "{name} names no glibc floor");
            floors.extend(claims);
        }
        floors.dedup();
        assert_eq!(
            floors.len(),
            1,
            "the READMEs name several floors: {floors:?}"
        );
        check_glibc_floor(
            README,
            &fs::read_to_string(root.join(README)).unwrap(),
            &floors[0],
        )
        .unwrap();
    }

    /// The README a zip carries says how to run what the zip holds.
    #[test]
    fn the_release_readme_names_what_the_zip_holds() {
        let root = crate::workspace_root().unwrap();
        let readme = fs::read_to_string(root.join(README)).unwrap();
        // Sentences wrap in the file; compare with every run of white space as one space.
        let readme = readme.split_whitespace().collect::<Vec<_>>().join(" ");
        for needle in [
            "tornect doctor",
            "tornect host",
            "tornect connect",
            "pt/lyrebird",
            "BUILD-INFO.txt",
            "THIRD_PARTY_LICENSES.txt",
            "SHA256SUMS",
            "Allow Remote Interaction",
            "Ctrl-C",
            // Slice-F F2-1: what the Linux start-at-login host does.
            "the host answers pings only and refuses every session, because it has no window \
             or terminal to show one",
            // polkit's policy file, in the Linux zip (decision M1-89).
            "| `polkit/org.tornect.policy` (Linux only) |",
            "sudo install -m 0644 polkit/org.tornect.policy /usr/share/polkit-1/actions/",
            "systemctl restart polkit",
            // A window-subsystem `tornect.exe` and its named pipe (the final audit).
            "start /wait tornect.exe host",
            "start /wait tornect.exe panic",
            // Invitations, links and the install (decision M1-73, §B.1.1).
            "Copy invitation",
            "tornect id --invitation",
            "tornect install",
            "tornect uninstall",
            // Unattended access, end to end (§B.8).
            "Connect without asking",
            "tornect unattended grant",
            "tornect connect --unattended",
            "emergency stop code",
            // The Windows zip's lyrebird and its install (decision M1-88 (2), W4).
            "`lyrebird.exe` beside `tornect.exe`",
        ] {
            assert!(
                readme.contains(needle),
                "README-release.md lacks `{needle}`"
            );
        }
        // What an earlier build said and this one no longer does.
        for stale in [
            "`tornect.exe` is a console program",
            "cannot reach a running Windows host",
            // Before decision M1-89 the policy came from the source tree.
            "not in this zip",
            "packaging/polkit/",
            // Before W4 the Windows zip held `pt\lyrebird.exe` and its
            // install carried none.
            "pt\\lyrebird.exe",
            "carries no lyrebird",
        ] {
            assert!(
                !readme.contains(stale),
                "README-release.md still says `{stale}`"
            );
        }
    }

    /// The first literal of `const NAME: (&str, &str) = ("…", "…");` in
    /// Rust source (a switch's title and its line).
    fn str_pair_first(src: &str, name: &str) -> String {
        let decl = format!("const {name}: (&str, &str) = (");
        let start = src.find(&decl).unwrap_or_else(|| panic!("no `{name}`")) + decl.len();
        let body = src[start..]
            .trim_start()
            .strip_prefix('"')
            .unwrap_or_else(|| panic!("`{name}` does not start with a literal"));
        body[..body
            .find('"')
            .unwrap_or_else(|| panic!("`{name}` never ends"))]
            .to_owned()
    }

    #[test]
    fn str_pair_first_reads_the_title() {
        let src =
            "pub(in x) const A: (&str, &str) = (\n    \"Chat\",\n    \"They \\\n write.\",\n);\n";
        assert_eq!(str_pair_first(src, "A"), "Chat");
    }

    /// `field: <n>,` in the `impl Default for <ty>` block of Rust source.
    fn default_number(src: &str, ty: &str, field: &str) -> u64 {
        let block = &src[src
            .find(&format!("impl Default for {ty} {{"))
            .unwrap_or_else(|| panic!("no `impl Default for {ty}`"))..];
        let block = &block[..block.find("\n}\n").unwrap_or(block.len())];
        let at = block
            .find(&format!("{field}: "))
            .unwrap_or_else(|| panic!("`{ty}::default` sets no `{field}`"))
            + field.len()
            + 2;
        let digits: String = block[at..]
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        digits
            .parse()
            .unwrap_or_else(|_| panic!("`{field}` is not a number"))
    }

    #[test]
    fn default_number_reads_a_field_of_its_block() {
        let src = "impl Default for B {\n    fn default() -> Self {\n        Self { n: 7 }\n    }\n}\n\
                   impl Default for A {\n    fn default() -> Self {\n        Self {\n            \
                   n: 2048,\n        }\n    }\n}\n";
        assert_eq!(default_number(src, "A", "n"), 2048);
        assert_eq!(default_number(src, "B", "n"), 7);
    }

    /// The release README's "Chat, clipboard and files" names the switches
    /// Settings › Sharing draws and the limits `[services]` defaults to (the
    /// final audit before the release: it said nothing of them, while a
    /// viewer with control may see and copy any file by default). The words
    /// and the numbers are read from source, so neither can change without
    /// the README.
    #[test]
    fn the_release_readme_names_the_sharing_switches_and_limits() {
        let root = crate::workspace_root().unwrap();
        let readme = fs::read_to_string(root.join(README)).unwrap();
        let readme = readme.split_whitespace().collect::<Vec<_>>().join(" ");
        let sharing =
            fs::read_to_string(root.join("apps/tornect/src/ui/pages/settings/sharing.rs")).unwrap();
        let strip = fs::read_to_string(root.join("apps/tornect/src/ui/view/strip.rs")).unwrap();
        let config = fs::read_to_string(root.join("crates/tornect-core/src/config.rs")).unwrap();
        let mut needed: Vec<String> = ["CHAT", "CLIPBOARD", "RECEIVE", "BROWSE", "SHARE_CLIPBOARD"]
            .map(|name| format!("**{}**", str_pair_first(&sharing, name)))
            .into();
        needed.push(format!("**{}**", str_const(&strip, "TURN_OFF")));
        for (field, words) in [
            ("max_file_mib", "each file up to {} GiB (`max_file_mib`)"),
            ("session_quota_mib", "up to {} GiB (`session_quota_mib`)"),
            (
                "keep_free_mib",
                "{} GiB of the disk always kept free (`keep_free_mib`)",
            ),
        ] {
            let mib = default_number(&config, "Services", field);
            assert_eq!(
                mib % 1024,
                0,
                "`{field}` is not whole GiB: say it otherwise"
            );
            needed.push(words.replace("{}", &(mib / 1024).to_string()));
        }
        assert!(
            config.contains("wayland_clipboard: false,"),
            "`wayland_clipboard` is no longer off by default: the README says it is"
        );
        needed.extend(["wayland_clipboard", "clipboard_sync", "200 KB/s"].map(str::to_owned));
        for needle in &needed {
            assert!(
                readme.contains(needle.as_str()),
                "README-release.md lacks `{needle}`"
            );
        }
    }

    /// The release notes under `packaging/release/`: every `NOTES-*.md`.
    fn release_notes(root: &Path) -> Vec<(String, String)> {
        let mut notes: Vec<(String, String)> = fs::read_dir(root.join("packaging/release"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("NOTES-") && n.ends_with(".md"))
            .map(|n| {
                let text = fs::read_to_string(root.join("packaging/release").join(&n)).unwrap();
                (n, text.split_whitespace().collect::<Vec<_>>().join(" "))
            })
            .collect();
        notes.sort();
        notes
    }

    /// No release notes say what this build no longer does (the final
    /// audit: the slice's notes said every session went over Tor and no
    /// client asked for an unattended session, and described a console
    /// `tornect.exe` that could not reach its host's control channel; the
    /// slice.2 notes said the Windows install carried no lyrebird).
    #[test]
    fn no_release_notes_say_what_this_build_no_longer_does() {
        let root = crate::workspace_root().unwrap();
        let direct = fs::read_to_string(root.join("crates/tornect-session/src/direct.rs")).unwrap();
        let notes = release_notes(&root);
        assert!(
            !notes.is_empty(),
            "no release notes under packaging/release"
        );
        let mut stale = vec![
            "No client in this build asks for an unattended session",
            "`tornect.exe` is a console program",
            "cannot reach a running Windows host",
            // Before decision M1-88 (2), W4.
            "carries no lyrebird",
        ];
        if direct.contains("pub const INTERNET_DIRECT: bool = true;") {
            stale.extend([
                "Everything travels over Tor",
                "Pictures and input travel over the Tor circuit",
            ]);
        }
        for (name, text) in &notes {
            for words in &stale {
                assert!(!text.contains(words), "{name} still says `{words}`");
            }
        }
    }

    /// The documentation pass's security review: with direct connections
    /// over the internet on, the defaults ask a public STUN server and the
    /// router (UPnP, NAT-PMP or PCP opens a port), so the front page, the
    /// zipped README and this pre-release's notes do not say "no port
    /// forwarding" (the slice.1 notes, of a build whose sessions all went
    /// over Tor, keep it).
    #[test]
    fn the_documents_of_this_build_do_not_claim_no_port_forwarding() {
        let root = crate::workspace_root().unwrap();
        let direct = fs::read_to_string(root.join("crates/tornect-session/src/direct.rs")).unwrap();
        if !direct.contains("pub const INTERNET_DIRECT: bool = true;") {
            return;
        }
        for name in [
            "README.md",
            README,
            "packaging/release/NOTES-v0.1.0-slice.2.md",
        ] {
            let text = fs::read_to_string(root.join(name)).unwrap();
            let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
            assert!(
                !text.contains("no port forwarding"),
                "{name} says `no port forwarding`"
            );
        }
    }

    /// The text of `const NAME: &str = "…";` in Rust source: the literal
    /// with its line continuations (a backslash, the line break and the
    /// next line's leading white space) removed and `\"` read as `"`.
    fn str_const(src: &str, name: &str) -> String {
        let decl = format!("const {name}: &str = \"");
        let start = src.find(&decl).unwrap_or_else(|| panic!("no `{name}`")) + decl.len();
        let body = &src[start..];
        let body = &body[..body
            .find("\";")
            .unwrap_or_else(|| panic!("`{name}` never ends"))];
        let mut text = String::new();
        let mut chars = body.chars().peekable();
        while let Some(c) = chars.next() {
            match (c, chars.next_if(|_| c == '\\')) {
                ('\\', Some('\n')) => while chars.next_if(|c| c.is_whitespace()).is_some() {},
                ('\\', Some(escaped)) => text.push(escaped),
                (c, _) => text.push(c),
            }
        }
        text
    }

    #[test]
    fn str_const_reads_a_continued_literal() {
        let src = "pub(in x) const A: &str = \"one \\\n          two \\\"q\\\"\";\n";
        assert_eq!(str_const(src, "A"), "one two \"q\"");
    }

    /// The release README's "Direct connections" names the switches this
    /// build draws (design `direct` §3.3; the review of steps B12 and B13):
    /// the words are read from the window's source and the scope from
    /// `INTERNET_DIRECT`, so neither can change without the README.
    #[test]
    fn the_release_readme_names_this_builds_direct_switches() {
        let root = crate::workspace_root().unwrap();
        let readme = fs::read_to_string(root.join(README)).unwrap();
        let readme = readme.split_whitespace().collect::<Vec<_>>().join(" ");
        let direct = fs::read_to_string(root.join("crates/tornect-session/src/direct.rs")).unwrap();
        let internet = if direct.contains("pub const INTERNET_DIRECT: bool = true;") {
            true
        } else {
            assert!(
                direct.contains("pub const INTERNET_DIRECT: bool = false;"),
                "INTERNET_DIRECT's value is not found"
            );
            false
        };
        let page =
            fs::read_to_string(root.join("apps/tornect/src/ui/pages/settings/connection.rs"))
                .unwrap();
        let (this, other) = if internet {
            ("DIRECT_SWITCH_INTERNET", "DIRECT_SWITCH_LAN")
        } else {
            ("DIRECT_SWITCH_LAN", "DIRECT_SWITCH_INTERNET")
        };
        let mut needed = vec![str_const(&page, this)];
        if internet {
            needed.extend(["STUN_SWITCH", "ROUTER_SWITCH"].map(|name| str_const(&page, name)));
            needed.extend(
                [
                    "ROUTE direct internet",
                    "stun_servers",
                    "direct_with_bridges",
                    "--tor-only",
                    "lan_only",
                    "paranoid = true",
                ]
                .map(str::to_owned),
            );
        }
        for needle in &needed {
            assert!(
                readme.contains(needle.as_str()),
                "README-release.md lacks `{needle}`"
            );
        }
        // The other build's switch: its words before the parenthesis.
        let other = str_const(&page, other);
        let other = other.split(" (").next().unwrap_or(&other);
        assert!(
            !readme.contains(other),
            "README-release.md names `{other}`, a switch this build does not draw"
        );
        if internet {
            assert!(
                !readme.contains("every session still goes over Tor"),
                "README-release.md says internet sessions stay on Tor"
            );
            // The documentation pass's security review: PCP defines an
            // optional description (RFC 7220); what is true is that Tornect's
            // requests send none (tornect-net `mapping/nat.rs` `options`).
            assert!(
                readme.contains("Tornect's PCP and NAT-PMP requests carry no name"),
                "README-release.md does not say that Tornect's PCP and NAT-PMP requests carry no \
                 name"
            );
            assert!(
                !readme.contains("PCP and NAT-PMP have no field"),
                "README-release.md says PCP has no field for a name"
            );
        }
    }

    /// The string literals between `const NAME` and the `];` that ends its
    /// array, in order.
    fn array_strs(src: &str, name: &str) -> Vec<String> {
        let decl = format!("const {name}: ");
        let start = src.find(&decl).unwrap_or_else(|| panic!("no `{name}`"));
        let body = &src[start..];
        let body = &body[..body
            .find("];")
            .unwrap_or_else(|| panic!("`{name}` never ends"))];
        body.split('"')
            .skip(1)
            .step_by(2)
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn array_strs_reads_every_literal() {
        let src =
            "pub const M: [(K, &str); 2] = [\n    (K::A, \"One\"),\n    (K::B, \"Two\"),\n];\n";
        assert_eq!(array_strs(src, "M"), ["One", "Two"]);
    }

    /// The release README's "Where Tor is blocked" and "A new Tornect ID"
    /// name the ways to Tor, the private bridges and Rotate ID as the
    /// window and the command line offer them (the closing gate's
    /// completeness check: both were built and the README named neither).
    #[test]
    fn the_release_readme_names_the_ways_to_tor_and_rotate_id() {
        let root = crate::workspace_root().unwrap();
        let readme = fs::read_to_string(root.join(README)).unwrap();
        let readme = readme.split_whitespace().collect::<Vec<_>>().join(" ");
        let connection =
            fs::read_to_string(root.join("apps/tornect/src/ui/pages/settings/connection.rs"))
                .unwrap();
        let security =
            fs::read_to_string(root.join("apps/tornect/src/ui/pages/settings/security.rs"))
                .unwrap();
        let config = fs::read_to_string(root.join("crates/tornect-core/src/config.rs")).unwrap();
        let main = fs::read_to_string(root.join("apps/tornect/src/main.rs")).unwrap();

        let modes = array_strs(&connection, "MODES");
        assert_eq!(modes.len(), 4, "the ways to Tor changed: {modes:?}");
        let mut needed = modes;
        assert!(
            connection.contains("section_header(ui, \"Private bridges\")"),
            "Settings › Connection no longer draws `Private bridges`"
        );
        needed.push("**Private bridges**".to_owned());
        assert!(
            config.contains("pub bridge_lines: Vec<String>,")
                && config.contains("pub bridges: BridgeMode,"),
            "`[tor]` no longer has `bridges` and `bridge_lines`"
        );
        needed.extend(
            [
                "bridge_lines",
                "bridges = \"auto\"",
                "--bridges auto|off|obfs4|snowflake",
                "tornect tor-check",
                "bridges.torproject.org",
            ]
            .map(str::to_owned),
        );
        needed.push(format!("**{}**", str_const(&security, "ROTATE")));
        assert!(
            main.contains("RotateId {"),
            "the command line no longer has `rotate-id`"
        );
        needed.push("tornect rotate-id --yes".to_owned());
        for needle in &needed {
            assert!(
                readme.contains(needle.as_str()),
                "README-release.md lacks `{needle}`"
            );
        }
    }
}
