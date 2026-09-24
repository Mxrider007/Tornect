//! `cargo xtask pt-fetch`: lyrebird, the pluggable transport a release ships
//! next to `tornect` (decision M1-38), fetched from the Tor Project's archive
//! and checked against the pins of `packaging/pt/SOURCES.md`.
//!
//! Nothing counts as checked because it is already on disk. A cached tarball is
//! used only when its SHA-256 equals the pin. The detached signature is checked
//! with the pinned Tor Browser Developers key whenever `gpg` and `gpgv` are
//! installed, and the run says plainly when they are not. The two members are
//! hashed after extraction and again after copying, and only then renamed into
//! `target/pt/<os>/`, under the paths they have in the tarball
//! (`tor/pluggable_transports/lyrebird`, `docs/lyrebird.txt`: the live-check
//! drivers point `TORNECT_PT_DIR` there). Any mismatch stops the run before
//! anything is installed.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context as _, bail, ensure};

use crate::sha256;

/// The Tor Browser release whose tor-expert-bundle carries the pinned lyrebird.
pub const TOR_BROWSER: &str = "15.0.23";
/// The lyrebird version inside it.
pub const LYREBIRD_VERSION: &str = "0.8.1";
const ARCHIVE: &str = "https://archive.torproject.org/tor-package-archive/torbrowser";
/// Primary key fingerprint of "Tor Browser Developers (signing key)".
pub const SIGNING_KEY: &str = "EF6E286DDA85EA2A4BA7DE684E2C6E8793298290";
/// That key, as exported from the Tor Project's WKD on 2026-09-21.
const SIGNING_KEY_FILE: &str = "packaging/pt/tor-browser-developers.asc";
/// lyrebird's licence notice; the same file in both tarballs.
pub const NOTICE: &str = "docs/lyrebird.txt";
const NOTICE_SHA256: &str = "2331e6517a15ce87e2a1d2838c314ca1b8f3c7a347ac28d370a7fccdb5964f40";
/// Where a release enforces the member pins at run time (`LYREBIRD_SHA256`).
const COMPILED_PINS: &str = "crates/tornect-signal/src/tor/bridges.rs";
const SOURCES: &str = "packaging/pt/SOURCES.md";

/// One platform's tor-expert-bundle and the two files a release takes from it.
#[derive(Debug, Clone, Copy)]
pub struct Bundle {
    /// The tarball's name for the platform; also the directory under `target/pt/`.
    pub os: &'static str,
    pub tarball_sha256: &'static str,
    /// lyrebird's path inside the tarball.
    pub member: &'static str,
    pub member_sha256: &'static str,
    pub notice_sha256: &'static str,
}

pub const LINUX: Bundle = Bundle {
    os: "linux-x86_64",
    tarball_sha256: "08d49de27f542b8f73e2014e064d8320562b5d20019c03d4725c5a5249d97985",
    member: "tor/pluggable_transports/lyrebird",
    member_sha256: "ee13ec155cf9b131a3e1b87bd6d697a10c42d04f2eaaeab6b1590c9971d41421",
    notice_sha256: NOTICE_SHA256,
};

pub const WINDOWS: Bundle = Bundle {
    os: "windows-x86_64",
    tarball_sha256: "231dad6b9cb401a54c260db7046965ef04e4f72ff071b140d423fb5da281ab1e",
    member: "tor/pluggable_transports/lyrebird.exe",
    member_sha256: "6e218e85f9a7ae2481f5402ded822471a9a9d0c7e66b05db3842b93fa5c1f02e",
    notice_sha256: NOTICE_SHA256,
};

impl Bundle {
    pub fn tarball(&self) -> String {
        format!("tor-expert-bundle-{}-{TOR_BROWSER}.tar.gz", self.os)
    }

    fn url(&self) -> String {
        format!("{ARCHIVE}/{TOR_BROWSER}/{}", self.tarball())
    }

    /// `lyrebird` or `lyrebird.exe`.
    pub fn file_name(&self) -> &'static str {
        self.member.rsplit('/').next().unwrap_or(self.member)
    }
}

/// What one run checked, and where it put the two files.
#[derive(Debug)]
pub struct Fetched {
    pub lyrebird: PathBuf,
    pub notice: PathBuf,
    pub signature: Signature,
}

/// The outcome of the signature check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signature {
    /// A good signature by the pinned key (or one of its subkeys).
    Good {
        /// Fingerprint of the key that made it.
        signer: String,
        /// When it was made, `YYYY-MM-DD`.
        made: String,
        /// That key has expired since; the signature was made while it was valid.
        key_expired: bool,
    },
    /// Not checked, and why.
    NotChecked(String),
}

impl std::fmt::Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Good {
                signer,
                made,
                key_expired,
            } => {
                write!(
                    f,
                    "good: made {made} by {signer}, whose primary key is the pinned Tor \
                     Browser Developers key {SIGNING_KEY}"
                )?;
                if *key_expired {
                    write!(f, " (that key has expired since)")?;
                }
                Ok(())
            }
            Self::NotChecked(why) => {
                write!(f, "NOT CHECKED ({why}); only the SHA-256 pins were checked")
            }
        }
    }
}

/// `cargo xtask pt-fetch [--linux] [--windows] [--offline]` (both platforms by default).
pub fn pt_fetch(root: &Path, args: &[String]) -> anyhow::Result<()> {
    let mut offline = false;
    let mut bundles = Vec::new();
    for arg in args {
        match arg.as_str() {
            "--offline" => offline = true,
            "--linux" => bundles.push(LINUX),
            "--windows" => bundles.push(WINDOWS),
            other => bail!(
                "pt-fetch: unknown argument `{other}` (expected --linux, --windows or --offline)"
            ),
        }
    }
    if bundles.is_empty() {
        bundles = vec![LINUX, WINDOWS];
    }
    for bundle in bundles {
        let fetched = fetch(root, bundle, offline)?;
        println!(
            "pt-fetch: {} ok: {} and {}; signature {}",
            bundle.os,
            fetched.lyrebird.display(),
            fetched.notice.display(),
            fetched.signature
        );
    }
    Ok(())
}

/// Fetch or reuse one platform's tarball, check it, and install lyrebird and
/// its notice under `target/pt/<os>/`.
pub fn fetch(root: &Path, bundle: Bundle, offline: bool) -> anyhow::Result<Fetched> {
    check_pins(root)?;
    let layout = Layout {
        cache: root.join("target").join("pt-fetch").join(TOR_BROWSER),
        dest: root.join("target").join("pt"),
    };
    let key = root.join(SIGNING_KEY_FILE);
    let download = |url: &str, to: &Path| -> anyhow::Result<()> {
        if offline {
            bail!("--offline: not downloading {url}");
        }
        curl(url, to)
    };
    let verify = |file: &Path, sig: &Path| gpg_verify(&key, &layout.cache, file, sig);
    println!(
        "==> pt-fetch {} (Tor Browser {TOR_BROWSER}, lyrebird {LYREBIRD_VERSION})",
        bundle.os
    );
    fetch_with(&layout, bundle, &download, &verify)
}

struct Layout {
    /// Downloads: `target/pt-fetch/<Tor Browser version>/`.
    cache: PathBuf,
    /// Installs: `target/pt/`.
    dest: PathBuf,
}

type Download<'a> = &'a dyn Fn(&str, &Path) -> anyhow::Result<()>;
type Verify<'a> = &'a dyn Fn(&Path, &Path) -> anyhow::Result<Signature>;

fn fetch_with(
    layout: &Layout,
    bundle: Bundle,
    download: Download<'_>,
    verify: Verify<'_>,
) -> anyhow::Result<Fetched> {
    fs::create_dir_all(&layout.cache)
        .with_context(|| format!("creating {}", layout.cache.display()))?;
    let tarball = layout.cache.join(bundle.tarball());
    obtain(
        &tarball,
        &bundle.url(),
        Some(bundle.tarball_sha256),
        download,
    )?;
    let sig = layout.cache.join(format!("{}.asc", bundle.tarball()));
    obtain(&sig, &format!("{}.asc", bundle.url()), None, download)?;
    let signature = verify(&tarball, &sig)?;
    println!("    signature {signature}");

    let scratch = Scratch::create(layout.cache.join(format!(
        "extract-{}-{}",
        bundle.os,
        std::process::id()
    )))?;
    untar(&tarball, scratch.path(), &[bundle.member, NOTICE])?;
    let member = scratch.path().join(bundle.member);
    let notice = scratch.path().join(NOTICE);
    check_file(&member, bundle.member_sha256)?;
    check_file(&notice, bundle.notice_sha256)?;
    println!("    {} and {NOTICE}: SHA-256 match the pins", bundle.member);

    let dest = layout.dest.join(bundle.os);
    let lyrebird = install(
        &member,
        &dest.join(bundle.member),
        0o755,
        bundle.member_sha256,
    )?;
    let notice = install(&notice, &dest.join(NOTICE), 0o644, bundle.notice_sha256)?;
    println!("    installed under {}", dest.display());
    Ok(Fetched {
        lyrebird,
        notice,
        signature,
    })
}

/// Make `path` hold the file at `url`. A cached copy is kept only when its
/// SHA-256 is `pin`; a download goes to `<name>.part`, is hashed, and is renamed
/// into place only when it matches. Without a pin (the `.asc`), the signature
/// check that follows judges the file.
fn obtain(path: &Path, url: &str, pin: Option<&str>, download: Download<'_>) -> anyhow::Result<()> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if path.is_file() {
        let Some(pin) = pin else {
            println!("    {name}: cached");
            return Ok(());
        };
        let got = sha256::file_hex(path).with_context(|| format!("hashing {}", path.display()))?;
        if got == pin {
            println!("    {name}: cached, SHA-256 matches the pin");
            return Ok(());
        }
        println!(
            "    {name}: the cached copy's SHA-256 is {got}, not the pinned {pin}; deleting it \
             and downloading again"
        );
        fs::remove_file(path).with_context(|| format!("deleting {}", path.display()))?;
    }
    let part = path.with_file_name(format!("{name}.part"));
    let _ = fs::remove_file(&part);
    println!("    {name}: downloading {url}");
    let fetched = download(url, &part).and_then(|()| match pin {
        None => Ok(()),
        Some(pin) => {
            let got =
                sha256::file_hex(&part).with_context(|| format!("hashing {}", part.display()))?;
            ensure!(
                got == pin,
                "{name}: the download's SHA-256 is {got}, not the pinned {pin}; deleted it, \
                 nothing installed"
            );
            Ok(())
        }
    });
    if let Err(e) = fetched {
        let _ = fs::remove_file(&part);
        return Err(e);
    }
    fs::rename(&part, path).with_context(|| format!("renaming {} into place", part.display()))?;
    if pin.is_some() {
        println!("    {name}: downloaded, SHA-256 matches the pin");
    }
    Ok(())
}

/// Refuse a file whose SHA-256 is not `pin`.
pub(crate) fn check_file(path: &Path, pin: &str) -> anyhow::Result<()> {
    let got = sha256::file_hex(path).with_context(|| format!("hashing {}", path.display()))?;
    ensure!(
        got == pin,
        "{}: SHA-256 {got} is not the pinned {pin}; refusing it, nothing installed",
        path.display()
    );
    Ok(())
}

/// Copy a checked file to `to` under a temporary name, set its mode, check the
/// copy itself, then rename it over whatever was there.
fn install(from: &Path, to: &Path, mode: u32, pin: &str) -> anyhow::Result<PathBuf> {
    let dir = to.parent().context("an install path has a parent")?;
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let name = to
        .file_name()
        .context("an install path has a file name")?
        .to_string_lossy();
    let tmp = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    let placed = fs::copy(from, &tmp)
        .map_err(anyhow::Error::from)
        .and_then(|_| set_mode(&tmp, mode))
        .and_then(|()| check_file(&tmp, pin))
        .and_then(|()| fs::rename(&tmp, to).map_err(anyhow::Error::from));
    if let Err(e) = placed {
        let _ = fs::remove_file(&tmp);
        return Err(e.context(format!("installing {}", to.display())));
    }
    Ok(to.to_path_buf())
}

#[cfg(unix)]
pub(crate) fn set_mode(path: &Path, mode: u32) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("setting the mode of {}", path.display()))
}

#[cfg(not(unix))]
pub(crate) fn set_mode(_path: &Path, _mode: u32) -> anyhow::Result<()> {
    Ok(())
}

/// A directory that is removed again when dropped, whatever happened meanwhile.
pub(crate) struct Scratch(PathBuf);

impl Scratch {
    pub(crate) fn create(path: PathBuf) -> anyhow::Result<Self> {
        if path.exists() {
            fs::remove_dir_all(&path).with_context(|| format!("removing {}", path.display()))?;
        }
        fs::create_dir_all(&path).with_context(|| format!("creating {}", path.display()))?;
        Ok(Self(path))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn untar(tarball: &Path, into: &Path, members: &[&str]) -> anyhow::Result<()> {
    let status = Command::new("tar")
        .arg("-xzf")
        .arg(tarball)
        .arg("-C")
        .arg(into)
        .arg("--no-same-owner")
        .args(members)
        .status()
        .context("running `tar`")?;
    ensure!(
        status.success(),
        "`tar` could not extract {} from {} ({status})",
        members.join(" and "),
        tarball.display()
    );
    Ok(())
}

/// `--disable` comes first so that `~/.curlrc` is not read: the request carries
/// curl's default user agent and nothing a local configuration would add.
fn curl(url: &str, to: &Path) -> anyhow::Result<()> {
    let status = Command::new("curl")
        .args([
            "--disable",
            "--fail",
            "--location",
            "--silent",
            "--show-error",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--tlsv1.2",
            "--max-filesize",
            "104857600",
            "--connect-timeout",
            "30",
            "--retry",
            "2",
            "--output",
        ])
        .arg(to)
        .arg(url)
        .status()
        .context("running `curl` (needed to download; --offline uses the cache alone)")?;
    ensure!(
        status.success(),
        "`curl` could not download {url} ({status})"
    );
    Ok(())
}

/// Check `sig` over `file` with the pinned key alone. `gpg --dearmor` turns the
/// committed ASCII key into a keyring, and `gpgv` verifies against that keyring
/// in an empty home directory, so no local key, configuration or trust setting
/// takes part.
fn gpg_verify(key: &Path, cache: &Path, file: &Path, sig: &Path) -> anyhow::Result<Signature> {
    let (Some(gpg), Some(gpgv)) = (crate::find_on_path("gpg"), crate::find_on_path("gpgv")) else {
        return Ok(Signature::NotChecked(
            "`gpg` and `gpgv` are not both on PATH".to_owned(),
        ));
    };
    let home = Scratch::create(cache.join(format!("gnupg-{}", std::process::id())))?;
    set_mode(home.path(), 0o700)?;
    let keyring = home.path().join("tor-browser-developers.gpg");
    let out = Command::new(gpg)
        .arg("--homedir")
        .arg(home.path())
        .args(["--batch", "--no-autostart", "--dearmor", "--output"])
        .arg(&keyring)
        .arg(key)
        .output()
        .context("running `gpg --dearmor`")?;
    ensure!(
        out.status.success(),
        "`gpg --dearmor {}` failed: {}",
        key.display(),
        String::from_utf8_lossy(&out.stderr).trim()
    );
    let out = Command::new(gpgv)
        .arg("--homedir")
        .arg(home.path())
        .arg("--keyring")
        .arg(&keyring)
        .args(["--status-fd", "1"])
        .arg(sig)
        .arg(file)
        .output()
        .context("running `gpgv`")?;
    judge_signature(
        out.status.success(),
        &String::from_utf8_lossy(&out.stdout),
        SIGNING_KEY,
    )
    .with_context(|| {
        format!(
            "{} does not verify {} with the pinned Tor Browser Developers key {SIGNING_KEY}; \
             nothing installed (gpgv: {})",
            sig.display(),
            file.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        )
    })
}

/// Read `gpgv --status-fd` lines. Accepted only with all of: gpgv's success, a
/// `VALIDSIG` whose primary-key fingerprint is `pinned`, a `GOODSIG` (or an
/// `EXPKEYSIG`: good, by a key that has expired since), and no `BADSIG`,
/// `ERRSIG`, `NO_PUBKEY`, `REVKEYSIG` or `EXPSIG`.
fn judge_signature(exit_ok: bool, status: &str, pinned: &str) -> anyhow::Result<Signature> {
    let mut good = false;
    let mut key_expired = false;
    let mut valid = None;
    for line in status.lines() {
        let Some(rest) = line.strip_prefix("[GNUPG:] ") else {
            continue;
        };
        let fields: Vec<&str> = rest.split_whitespace().collect();
        match fields.first().copied() {
            Some("GOODSIG") => good = true,
            Some("EXPKEYSIG") => key_expired = true,
            Some(bad @ ("BADSIG" | "ERRSIG" | "NO_PUBKEY" | "REVKEYSIG" | "EXPSIG")) => {
                bail!("gpgv reported {bad}")
            }
            Some("VALIDSIG") => {
                // VALIDSIG <fpr> <date> <timestamp> <expire> <version> <reserved>
                //          <pubkey-algo> <hash-algo> <class> <primary-key-fpr>
                let primary = fields.get(10).copied().unwrap_or("(none)");
                ensure!(
                    primary.eq_ignore_ascii_case(pinned),
                    "made by a key whose primary is {primary}, not the pinned {pinned}"
                );
                valid = Some((
                    fields.get(1).copied().unwrap_or_default().to_owned(),
                    fields.get(2).copied().unwrap_or_default().to_owned(),
                ));
            }
            _ => {}
        }
    }
    ensure!(exit_ok, "gpgv did not accept the signature");
    let Some((signer, made)) = valid else {
        bail!("gpgv reported no valid signature");
    };
    ensure!(good || key_expired, "gpgv reported no good signature");
    Ok(Signature::Good {
        signer,
        made,
        key_expired,
    })
}

/// The pins above must be the ones a release enforces at run time
/// (`LYREBIRD_SHA256` in `tornect-signal`) and the ones `SOURCES.md` records.
pub fn check_pins(root: &Path) -> anyhow::Result<()> {
    let compiled = fs::read_to_string(root.join(COMPILED_PINS))
        .with_context(|| format!("reading {COMPILED_PINS}"))?;
    let sources =
        fs::read_to_string(root.join(SOURCES)).with_context(|| format!("reading {SOURCES}"))?;
    check_pins_in(&compiled, &sources)
}

fn check_pins_in(compiled: &str, sources: &str) -> anyhow::Result<()> {
    let found = compiled_pins(compiled)?;
    let want = vec![
        (LINUX.os, LINUX.member_sha256.to_owned()),
        (WINDOWS.os, WINDOWS.member_sha256.to_owned()),
    ];
    ensure!(
        found == want,
        "{COMPILED_PINS} pins {found:?}, but xtask pins {want:?}: change them together \
         ({SOURCES}, \"Updating\")"
    );
    for (label, value) in [
        ("upstream", TOR_BROWSER),
        ("upstream", LYREBIRD_VERSION),
        ("linux sha256", LINUX.tarball_sha256),
        ("windows sha256", WINDOWS.tarball_sha256),
        ("member (linux)", LINUX.member_sha256),
        ("member (windows)", WINDOWS.member_sha256),
        ("licence notice", NOTICE_SHA256),
        ("signing key", SIGNING_KEY),
    ] {
        let row = sources
            .lines()
            .find(|l| l.starts_with(&format!("| {label} |")))
            .with_context(|| format!("{SOURCES} has no `{label}` row"))?;
        let compact: String = row.chars().filter(|c| !c.is_whitespace()).collect();
        ensure!(
            compact.contains(value),
            "{SOURCES}'s `{label}` row does not say {value}, which xtask pins"
        );
    }
    Ok(())
}

/// `(platform, hash)` for each `pub const LYREBIRD_SHA256 … = Some("…")`, the
/// platform read from the `#[cfg(…)]` line above it.
fn compiled_pins(src: &str) -> anyhow::Result<Vec<(&'static str, String)>> {
    let lines: Vec<&str> = src.lines().collect();
    let mut pins = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if !line.contains("pub const LYREBIRD_SHA256") {
            continue;
        }
        let value = if line.trim_end().ends_with(';') {
            (*line).to_owned()
        } else {
            format!("{line} {}", lines.get(i + 1).copied().unwrap_or_default())
        };
        let Some(start) = value.find("Some(\"") else {
            continue; // the `None` of the platforms nothing is pinned for
        };
        let hex: String = value[start + 6..]
            .chars()
            .take_while(char::is_ascii_hexdigit)
            .collect();
        ensure!(
            hex.len() == 64,
            "{COMPILED_PINS}: a LYREBIRD_SHA256 value is not 64 hex digits"
        );
        let cfg = lines[..i]
            .iter()
            .rev()
            .find(|l| l.trim_start().starts_with("#[cfg("))
            .copied()
            .unwrap_or_default();
        let os = match (
            cfg.contains("target_os = \"linux\""),
            cfg.contains("windows"),
            cfg.contains("target_arch = \"x86_64\""),
        ) {
            (true, false, true) => LINUX.os,
            (false, true, true) => WINDOWS.os,
            _ => bail!(
                "{COMPILED_PINS}: cannot tell which platform `{}` pins",
                cfg.trim()
            ),
        };
        pins.push((os, hex));
    }
    Ok(pins)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("xtask-pt-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Only `fake_pins` calls it, and that exists only where `tar` makes the
    /// fake bundles; anywhere else (the gnullvm lint) it would be dead code.
    #[cfg(unix)]
    fn leak(s: String) -> &'static str {
        Box::leak(s.into_boxed_str())
    }

    fn never(url: &str, _: &Path) -> anyhow::Result<()> {
        panic!("nothing should be downloaded, yet {url} was asked for")
    }

    #[test]
    fn the_pins_match_bridges_rs_and_sources_md() {
        check_pins(&crate::workspace_root().unwrap()).unwrap();
    }

    #[test]
    fn a_pin_that_drifts_from_bridges_rs_or_sources_md_is_refused() {
        let root = crate::workspace_root().unwrap();
        let compiled = fs::read_to_string(root.join(COMPILED_PINS)).unwrap();
        let sources = fs::read_to_string(root.join(SOURCES)).unwrap();
        let zeros = "0".repeat(64);

        let drifted = compiled.replace(LINUX.member_sha256, &zeros);
        let err = check_pins_in(&drifted, &sources).unwrap_err().to_string();
        assert!(err.contains("change them together"), "{err}");

        let drifted = sources.replace(WINDOWS.tarball_sha256, &zeros);
        let err = check_pins_in(&compiled, &drifted).unwrap_err().to_string();
        assert!(err.contains("`windows sha256` row"), "{err}");

        let swapped = compiled.replace("target_os = \"linux\"", "windows");
        assert!(check_pins_in(&swapped, &sources).is_err());
    }

    const PRIMARY: &str = SIGNING_KEY;

    fn validsig(primary: &str) -> String {
        format!(
            "[GNUPG:] VALIDSIG CAAE408AEBE2288E96FC5D5E157432CF78A65729 2026-09-15 1789430400 0 \
             4 0 1 10 00 {primary}"
        )
    }

    #[test]
    fn a_good_signature_by_the_pinned_key_is_accepted() {
        let status = format!(
            "[GNUPG:] NEWSIG\n[GNUPG:] KEY_CONSIDERED {PRIMARY} 0\n[GNUPG:] SIG_ID x 2026-09-15 \
             1789430400\n[GNUPG:] GOODSIG 157432CF78A65729 Tor Browser Developers (signing key) \
             <torbrowser@torproject.org>\n{}\n",
            validsig(PRIMARY)
        );
        assert_eq!(
            judge_signature(true, &status, PRIMARY).unwrap(),
            Signature::Good {
                signer: "CAAE408AEBE2288E96FC5D5E157432CF78A65729".to_owned(),
                made: "2026-09-15".to_owned(),
                key_expired: false,
            }
        );
        let expired = format!(
            "[GNUPG:] EXPKEYSIG 157432CF78A65729 x\n{}\n",
            validsig(PRIMARY)
        );
        assert!(matches!(
            judge_signature(true, &expired, PRIMARY).unwrap(),
            Signature::Good {
                key_expired: true,
                ..
            }
        ));
    }

    #[test]
    fn any_other_signature_is_refused() {
        let other = "0123456789ABCDEF0123456789ABCDEF01234567";
        for (exit_ok, status) in [
            // good, but by another primary key
            (true, format!("[GNUPG:] GOODSIG 1 x\n{}\n", validsig(other))),
            // a bad signature, even beside a valid one
            (
                false,
                format!("[GNUPG:] BADSIG 1 x\n{}\n", validsig(PRIMARY)),
            ),
            // no public key for it
            (
                false,
                "[GNUPG:] ERRSIG 1 1 10 00 1789430400 9\n[GNUPG:] NO_PUBKEY 1\n".to_owned(),
            ),
            // a revoked key
            (
                true,
                format!("[GNUPG:] REVKEYSIG 1 x\n{}\n", validsig(PRIMARY)),
            ),
            // GOODSIG without VALIDSIG
            (true, "[GNUPG:] GOODSIG 1 x\n".to_owned()),
            // VALIDSIG without GOODSIG
            (true, format!("{}\n", validsig(PRIMARY))),
            // everything right but gpgv's exit status
            (
                false,
                format!("[GNUPG:] GOODSIG 1 x\n{}\n", validsig(PRIMARY)),
            ),
            // nothing at all
            (true, String::new()),
        ] {
            assert!(
                judge_signature(exit_ok, &status, PRIMARY).is_err(),
                "accepted: {status:?}"
            );
        }
    }

    #[test]
    fn a_download_that_does_not_match_its_pin_is_deleted() {
        let dir = temp("bad-download");
        let path = dir.join("bundle.tar.gz");
        let pin = sha256::hex_digest(b"the real tarball");
        let serve = |_: &str, to: &Path| -> anyhow::Result<()> {
            fs::write(to, b"a fabricated tarball")?;
            Ok(())
        };
        let err = obtain(&path, "https://example.invalid/b", Some(&pin), &serve)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not the pinned"), "{err}");
        assert!(!path.exists());
        assert!(!dir.join("bundle.tar.gz.part").exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_cached_file_is_used_only_when_it_matches_its_pin() {
        let dir = temp("cache");
        let path = dir.join("bundle.tar.gz");
        let pin = sha256::hex_digest(b"the real tarball");

        // Matches: reused, nothing downloaded.
        fs::write(&path, b"the real tarball").unwrap();
        obtain(&path, "https://example.invalid/b", Some(&pin), &never).unwrap();

        // Tampered with: replaced by a good download.
        fs::write(&path, b"the real tarball, changed").unwrap();
        let downloads = Cell::new(0);
        let serve_real = |_: &str, to: &Path| -> anyhow::Result<()> {
            downloads.set(downloads.get() + 1);
            fs::write(to, b"the real tarball")?;
            Ok(())
        };
        obtain(&path, "https://example.invalid/b", Some(&pin), &serve_real).unwrap();
        assert_eq!(downloads.get(), 1);
        assert_eq!(fs::read(&path).unwrap(), b"the real tarball");

        // Tampered with, and the download is bad too: nothing is left.
        fs::write(&path, b"the real tarball, changed").unwrap();
        let serve_bad = |_: &str, to: &Path| -> anyhow::Result<()> {
            fs::write(to, b"a fabricated tarball")?;
            Ok(())
        };
        assert!(obtain(&path, "https://example.invalid/b", Some(&pin), &serve_bad).is_err());
        assert!(!path.exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A fake tor-expert-bundle, made with `tar` as the real one is read with it.
    #[cfg(unix)]
    fn fake_bundle(dir: &Path, member: &[u8]) -> PathBuf {
        let src = dir.join("src");
        fs::create_dir_all(src.join("tor/pluggable_transports")).unwrap();
        fs::create_dir_all(src.join("docs")).unwrap();
        fs::write(src.join("tor/pluggable_transports/lyrebird"), member).unwrap();
        fs::write(src.join(NOTICE), b"fake licence notice").unwrap();
        let tarball = dir.join("fake.tar.gz");
        let status = Command::new("tar")
            .arg("-czf")
            .arg(&tarball)
            .arg("-C")
            .arg(&src)
            .args(["tor", "docs"])
            .status()
            .unwrap();
        assert!(status.success());
        tarball
    }

    #[cfg(unix)]
    fn fake_pins(tarball: &Path, member_pin: String) -> Bundle {
        Bundle {
            os: "test-os",
            tarball_sha256: leak(sha256::file_hex(tarball).unwrap()),
            member: "tor/pluggable_transports/lyrebird",
            member_sha256: leak(member_pin),
            notice_sha256: leak(sha256::hex_digest(b"fake licence notice")),
        }
    }

    #[cfg(unix)]
    fn unchecked(_: &Path, _: &Path) -> anyhow::Result<Signature> {
        Ok(Signature::NotChecked("test".to_owned()))
    }

    #[cfg(unix)]
    #[test]
    fn a_bundle_whose_pins_all_match_is_installed_with_its_modes() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = temp("good-bundle");
        let tarball = fake_bundle(&dir, b"fake lyrebird");
        let bundle = fake_pins(&tarball, sha256::hex_digest(b"fake lyrebird"));
        let layout = Layout {
            cache: dir.join("cache"),
            dest: dir.join("pt"),
        };
        let serve = |_: &str, to: &Path| -> anyhow::Result<()> {
            fs::copy(&tarball, to)?;
            Ok(())
        };
        let fetched = fetch_with(&layout, bundle, &serve, &unchecked).unwrap();
        assert_eq!(
            fetched.lyrebird,
            dir.join("pt/test-os/tor/pluggable_transports/lyrebird")
        );
        assert_eq!(fs::read(&fetched.lyrebird).unwrap(), b"fake lyrebird");
        assert_eq!(fs::read(&fetched.notice).unwrap(), b"fake licence notice");
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&fetched.lyrebird), 0o755);
        assert_eq!(mode(&fetched.notice), 0o644);

        // Run again: the cache serves, and nothing is downloaded.
        fetch_with(&layout, bundle, &never, &unchecked).unwrap();
        let left: Vec<_> = fs::read_dir(&layout.cache)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(
            left.len(),
            2,
            "only the tarball and its .asc stay: {left:?}"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    /// The fabricated mismatch: the tarball matches its pin, but the lyrebird
    /// inside it does not match the member pin.
    #[cfg(unix)]
    #[test]
    fn a_member_that_does_not_match_its_pin_installs_nothing() {
        let dir = temp("bad-member");
        let tarball = fake_bundle(&dir, b"a planted lyrebird");
        let bundle = fake_pins(&tarball, sha256::hex_digest(b"fake lyrebird"));
        let layout = Layout {
            cache: dir.join("cache"),
            dest: dir.join("pt"),
        };
        let serve = |_: &str, to: &Path| -> anyhow::Result<()> {
            fs::copy(&tarball, to)?;
            Ok(())
        };
        let err = fetch_with(&layout, bundle, &serve, &unchecked)
            .unwrap_err()
            .to_string();
        assert!(err.contains("is not the pinned"), "{err}");
        assert!(!layout.dest.exists(), "something was installed");
        let left: Vec<_> = fs::read_dir(&layout.cache)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            left.iter().all(|n| !n.starts_with("extract-")),
            "the scratch directory stayed: {left:?}"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A refused signature stops the run before extraction.
    #[cfg(unix)]
    #[test]
    fn a_refused_signature_installs_nothing() {
        let dir = temp("bad-signature");
        let tarball = fake_bundle(&dir, b"fake lyrebird");
        let bundle = fake_pins(&tarball, sha256::hex_digest(b"fake lyrebird"));
        let layout = Layout {
            cache: dir.join("cache"),
            dest: dir.join("pt"),
        };
        let serve = |_: &str, to: &Path| -> anyhow::Result<()> {
            fs::copy(&tarball, to)?;
            Ok(())
        };
        let refuse =
            |_: &Path, _: &Path| -> anyhow::Result<Signature> { bail!("gpgv reported BADSIG") };
        assert!(fetch_with(&layout, bundle, &serve, &refuse).is_err());
        assert!(!layout.dest.exists(), "something was installed");
        fs::remove_dir_all(&dir).unwrap();
    }
}
