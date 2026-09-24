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
//! hold the build machine's home path; then
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

use crate::{licences, pt, sha256};

/// Everything dist writes lives under this directory of the workspace.
const OUT: &str = "target/dist";
const README: &str = "packaging/release/README-release.md";

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
    let mut platforms = Vec::new();
    for arg in args {
        match arg.as_str() {
            "--linux" => platforms.push(LINUX),
            "--windows" => platforms.push(WINDOWS),
            "--allow-dirty" => allow_dirty = true,
            other => bail!(
                "dist: unknown argument `{other}` (expected --linux, --windows or --allow-dirty)"
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

/// What `dist` checked before building, for BUILD-INFO.txt.
struct Checks<'a> {
    /// `cargo-deny --version`.
    deny: &'a str,
    db: &'a crate::AdvisoryDb,
    /// The advisories `deny.toml` ignores, which the check let through.
    ignored: &'a [crate::Ignored],
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
    /// `$HOME/`, which no file in a zip may contain.
    home: Option<String>,
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
        let home = std::env::var("HOME")
            .ok()
            .filter(|h| h.len() > 1)
            .map(|h| format!("{}/", h.trim_end_matches('/')));
        Ok(Self {
            rustc,
            sysroot,
            cargo,
            nasm,
            zip,
            cc,
            strip,
            mingw,
            home,
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
        linux_facts(&built)?
    };

    let stem = format!("tornect-{version}-{}", platform.name);
    let stage = out.join("stage");
    let dir = stage.join(&stem);
    if dir.exists() {
        fs::remove_dir_all(&dir).with_context(|| format!("removing {}", dir.display()))?;
    }
    fs::create_dir_all(dir.join("pt")).with_context(|| format!("creating {}", dir.display()))?;

    let strip_tool = strip(tools, platform, &built, &dir.join(platform.exe))?;
    pt::set_mode(&dir.join(platform.exe), 0o755)?;
    let lyrebird = format!("pt/{}", platform.bundle.file_name());
    place(
        &fetched.lyrebird,
        &dir.join(&lyrebird),
        0o755,
        Some(platform.bundle.member_sha256),
    )?;
    place(
        &fetched.notice,
        &dir.join("pt/lyrebird.txt"),
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
        if let Some(home) = &tools.home {
            let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            if let Some(at) = find(&bytes, home.as_bytes()) {
                bail!(
                    "{} holds this machine's home directory path at byte {at}; a zip must not \
                     carry it (the build's --remap-path-prefix list misses a path)",
                    path.display()
                );
            }
        }
        fs::File::open(&path)
            .and_then(|f| f.set_modified(stamp))
            .with_context(|| format!("setting the time of {}", path.display()))?;
    }

    let zip = out.join(format!("{stem}.zip"));
    make_zip(&stage, &stem, &files, &zip)?;
    Ok(zip)
}

/// The files a zip holds besides BUILD-INFO.txt, which lists their hashes.
fn zip_files(platform: Platform) -> Vec<String> {
    vec![
        platform.exe.to_owned(),
        format!("pt/{}", platform.bundle.file_name()),
        "pt/lyrebird.txt".to_owned(),
        "LICENSE".to_owned(),
        "THIRD_PARTY_NOTICES.md".to_owned(),
        licences::FILE.to_owned(),
        "README-release.md".to_owned(),
    ]
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

fn linux_facts(exe: &Path) -> anyhow::Result<Facts> {
    let dynamic = capture(Command::new("readelf").arg("-d").arg(exe))?;
    let needed: Vec<&str> = dynamic
        .lines()
        .filter(|l| l.contains("(NEEDED)"))
        .filter_map(|l| l.split('[').nth(1)?.split(']').next())
        .collect();
    for lib in &needed {
        ensure!(
            LINUX_LIBS.contains(lib),
            "{} loads {lib}, which a release must not depend on (a system liblzma means \
             LZMA_API_STATIC did not take)",
            exe.display()
        );
    }
    let symbols = capture(Command::new("objdump").arg("-T").arg(exe))?;
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
                "newest versions    {}, {} and {}: it needs a glibc and a libstdc++ that \
                 have them",
                newest("GLIBC_"),
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
    let _ = writeln!(
        s,
        "  profile       release (Cargo.toml): opt-level 3, lto \"thin\", codegen-units 1, \
         debug \"line-tables-only\""
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
    let _ = writeln!(s, "\nlyrebird (pt/)");
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
                "pt/lyrebird.txt",
            ] {
                assert!(
                    files.iter().any(|f| f == needed),
                    "{}: {needed} is not in the zip",
                    platform.name
                );
            }
        }
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
        ] {
            assert!(
                readme.contains(needle),
                "README-release.md lacks `{needle}`"
            );
        }
    }
}
