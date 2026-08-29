//! `cargo xtask <command>` — repository automation (`docs/PLAN.md` §D.5).
//!
//! * `verify`      — plan sync, forbidden-dependency check, fmt check, clippy
//!   `-D warnings` on all targets, tests, docs
//! * `lint-all`    — fmt check + clippy only
//! * `dist`        — release build into `dist/` (packaging grows in M8)
//! * `ffmpeg-fetch`— placeholder until the FFmpeg backend lands (M3)
//! * `soak`        — placeholder until the loopback demo lands (M3)

#![forbid(unsafe_code)]
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use anyhow::{Context as _, bail};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let root = workspace_root()?;
    match args.first().map(String::as_str) {
        Some("verify") => verify(&root, &args[1..]),
        Some("lint-all") => lint_all(&root),
        Some("dist") => dist(&root),
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
                "usage: cargo xtask <verify [--no-tests] | lint-all | dist | ffmpeg-fetch | soak>"
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

fn cargo() -> Command {
    Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned()))
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
/// (docs/notes/decisions.md M0-8).
fn plan_sync(root: &Path) -> anyhow::Result<()> {
    println!("==> plan sync (TORNECT_PLAN.md == docs/PLAN.md)");
    let a = std::fs::read(root.join("TORNECT_PLAN.md")).context("reading TORNECT_PLAN.md")?;
    let b = std::fs::read(root.join("docs").join("PLAN.md")).context("reading docs/PLAN.md")?;
    if a != b {
        bail!("TORNECT_PLAN.md and docs/PLAN.md differ; copy the edited one over the other");
    }
    println!("    ok");
    Ok(())
}

/// Crates that must never enter the dependency graph: a second rustls crypto
/// provider (`ring` is the only one, decision M1-3 and docs/research/quic.md
/// §1.3 — with two compiled in rustls refuses to pick one, and a dependency
/// installing its own would silently replace ours) and OpenSSL (the build must
/// need only a C compiler, docs/research/arti.md §4).
const FORBIDDEN_DEPS: [&str; 3] = ["aws-lc-rs", "aws-lc-sys", "openssl-sys"];

/// `cargo tree --workspace -i <crate>` exits non-zero with "did not match any
/// packages" exactly when the crate is absent from the resolved graph.
fn forbidden_deps(root: &Path) -> anyhow::Result<()> {
    println!(
        "==> forbidden dependencies absent ({})",
        FORBIDDEN_DEPS.join(", ")
    );
    for dep in FORBIDDEN_DEPS {
        let output = cargo()
            .args(["tree", "--workspace", "-i", dep])
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

fn verify(root: &Path, extra: &[String]) -> anyhow::Result<()> {
    let no_tests = extra.iter().any(|a| a == "--no-tests");
    plan_sync(root)?;
    forbidden_deps(root)?;
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

fn dist(root: &Path) -> anyhow::Result<()> {
    let mut build = cargo();
    build.args(["build", "--profile", "dist", "-p", "tornect"]);
    run(root, "cargo build --profile dist -p tornect", build)?;

    let bin = format!("tornect{}", std::env::consts::EXE_SUFFIX);
    let src = root.join("target").join("dist").join(&bin);
    let out_dir = root.join("dist");
    std::fs::create_dir_all(&out_dir)?;
    let dst = out_dir.join(format!(
        "tornect-{}-{}-{}{}",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH,
        std::env::consts::EXE_SUFFIX
    ));
    std::fs::copy(&src, &dst)
        .with_context(|| format!("copying {} to {}", src.display(), dst.display()))?;
    println!("dist: wrote {}", dst.display());
    println!(
        "dist: installers (MSI/winget, notarized .dmg, AppImage/Flatpak) are M8 work — see docs/PLAN.md."
    );
    Ok(())
}
