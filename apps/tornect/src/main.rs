//! `tornect` entry point: the desktop window with no subcommand (or `tornect
//! gui`), and the command line.
//!
//! Milestone 0 ships the identity/config commands; Milestone 1 adds `host`,
//! `ping` and `connect` over the live Tor network; the vertical slice adds the
//! window (`ui`, decision D10's egui-everywhere fallback); `demo` arrives with
//! later milestones (`docs/PLAN.md` Part C).

#![forbid(unsafe_code)]
#![allow(clippy::print_stdout, clippy::print_stderr)]

// `+crt-static` comes from `.cargo/config.toml`, and a `RUSTFLAGS` variable
// silently replaces it; a dynamically linked `tornect.exe` would then load
// libc++/libunwind through the DLL search order (SLICE-A1 A1-10).
#[cfg(all(windows, target_env = "gnu", not(target_feature = "crt-static")))]
compile_error!(
    "the Windows build must link the C runtime statically: build without RUSTFLAGS, \
     or add `-C target-feature=+crt-static` to it"
);

mod host;
mod prompt;
mod tor_cmd;
mod ui;
mod unattended;

use std::path::PathBuf;

use anyhow::Context as _;
use clap::{Parser, Subcommand};
use tornect_core::config::BridgeMode;
use tornect_core::keystore::{
    self, FileSecretStore, load_or_create_device_identity, load_or_create_host_identity,
};
use tornect_core::telemetry::{self, LogOptions};
use tornect_core::{Config, Paths};

#[derive(Parser, Debug)]
#[command(name = "tornect", version, about, long_about = None)]
struct Cli {
    /// Put all Tornect state under this directory (env: TORNECT_HOME).
    #[arg(long, global = true, env = tornect_core::paths::HOME_ENV, value_name = "DIR")]
    home: Option<PathBuf>,

    /// Log filter, e.g. `debug` or `tornect_signal=trace` (env: TORNECT_LOG).
    #[arg(long, global = true, value_name = "FILTER")]
    log: Option<String>,

    /// Emit JSON log lines on stderr.
    #[arg(long, global = true)]
    json_logs: bool,

    /// How to reach Tor: `auto` (direct, then obfs4 bridges, then Snowflake),
    /// `off` (direct only), `obfs4` or `snowflake`. Default: config `tor.bridges`.
    #[arg(long, global = true, value_name = "MODE", value_parser = parse_bridge_mode)]
    bridges: Option<BridgeMode>,

    /// Without a subcommand, the window opens (`tornect gui`).
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Open the Tornect window (the default): this machine's ID and Tor status,
    /// connect to another computer, and answer pairing and session requests in
    /// popups, with a banner and Stop while the screen is shared.
    Gui {
        /// What a session shares: `desktop` or `test-card` (see `host`).
        #[arg(long, value_enum, default_value_t = CaptureArg::Desktop)]
        capture: CaptureArg,
        /// Only connect to others: publish no ID and answer no requests.
        #[arg(long)]
        no_host: bool,
        /// Show every screen from synthetic state and start nothing (no Tor,
        /// no hosting): for checking the window itself.
        #[arg(long, hide = true)]
        preview: bool,
        /// With --preview: open on this page at rest (no question, no
        /// session) instead of showing every screen at once.
        #[arg(long, hide = true, value_enum, requires = "preview")]
        page: Option<PageArg>,
        /// With --preview: draw in this theme (dark unless given).
        #[arg(long, hide = true, value_enum, requires = "preview")]
        theme: Option<ThemeArg>,
    },
    /// Show this machine's Tornect ID (its onion v3 address), creating it on first run.
    Id {
        /// Print machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Generate a new Tornect ID. Invalidates every pairing and unattended grant.
    RotateId {
        /// Skip the confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
    /// Print the directories Tornect uses.
    Paths,
    /// Inspect or initialize the configuration file.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Report the environment (OS, session type, directories, identities).
    Doctor,
    /// Publish this machine's Tornect ID as a Tor onion service; answer pings,
    /// and pairing and session requests (asked on this terminal); share the
    /// screen with each accepted session.
    ///
    /// Prints `Tornect ID: <onion>` as soon as the service is launched and
    /// `REACHABLE` once the address is published on the Tor network. Ctrl-C stops
    /// hosting and ends every session.
    Host {
        /// Exit after the first answered ping or finished session (scripted verification).
        #[arg(long)]
        once: bool,
        /// Force proof-of-work introduction defense on (default: config `tor.pow_defense`).
        #[arg(long, conflicts_with = "no_pow")]
        pow: bool,
        /// Force proof-of-work introduction defense off.
        #[arg(long, conflicts_with = "pow")]
        no_pow: bool,
        /// What a session shares: `desktop` (the RemoteDesktop portal and
        /// PipeWire on a Wayland session, X11 on an X11 session, GDI on
        /// Windows) or `test-card` (a synthetic picture; the viewer's input
        /// goes nowhere).
        #[arg(long, value_enum, default_value_t = CaptureArg::Desktop)]
        capture: CaptureArg,
    },
    /// Manage unattended access: which devices may connect without asking.
    Unattended {
        #[command(subcommand)]
        action: unattended::UnattendedCmd,
    },
    /// List the devices this host has paired with.
    Devices {
        /// Print machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// End every session now and, on a second press within 2 s, turn unattended
    /// access off host-wide (§B.8.7.4).
    Panic,
    /// Register or remove Tornect's start-at-login entry.
    Service {
        #[command(subcommand)]
        action: unattended::ServiceCmd,
    },
    /// Export or import the unattended-access backup.
    Backup {
        #[command(subcommand)]
        action: unattended::BackupCmd,
    },
    /// Reach the Tor network (direct, obfs4 bridges or Snowflake, per `--bridges`)
    /// and report which transport worked.
    TorCheck,
    /// Connect to a host by Tornect ID over Tor and measure round-trip times.
    ///
    /// Uses this instance's own Tor state; run it under a different TORNECT_HOME
    /// than the host when both live on one machine.
    Ping {
        /// The host's Tornect ID (56-character onion address, with or without `.onion`).
        onion: String,
        /// Number of pings to send (a host answers at most 100 per session).
        #[arg(
            long,
            default_value_t = 3,
            value_parser = clap::value_parser!(u32)
                .range(1..=i64::from(tornect_signal::ping::MAX_PINGS_PER_SESSION))
        )]
        count: u32,
    },
    /// Connect to a host by Tornect ID over Tor: pair with it if it is new
    /// (both screens show a code to compare), then ask for a session its user
    /// must accept, receive the shared screen, and keep the session alive until
    /// Ctrl-C.
    ///
    /// There is no viewer window yet: the pictures are decoded and counted.
    /// Uses this instance's own Tor state; run it under a different TORNECT_HOME
    /// than the host when both live on one machine.
    Connect {
        /// The host's Tornect ID (56-character onion address, with or without `.onion`).
        onion: String,
        /// Pair with the host (if it is new) and stop there.
        #[arg(long)]
        pair_only: bool,
        /// Forget this host first, so the connection pairs again.
        #[arg(long)]
        forget: bool,
        /// End the session after this many pings instead of at Ctrl-C.
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
        pings: Option<u32>,
        /// Keep only the signaling session: open no media stream.
        #[arg(long)]
        no_video: bool,
    },
}

/// `tornect gui --preview --page`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum PageArg {
    /// Home.
    Home,
    /// The address book.
    AddressBook,
    /// Past sessions.
    Sessions,
    /// Settings.
    Settings,
    /// The widget gallery.
    Widgets,
}

impl From<PageArg> for ui::Page {
    fn from(arg: PageArg) -> Self {
        match arg {
            PageArg::Home => Self::Home,
            PageArg::AddressBook => Self::AddressBook,
            PageArg::Sessions => Self::Sessions,
            PageArg::Settings => Self::Settings,
            PageArg::Widgets => Self::Widgets,
        }
    }
}

/// `tornect gui --preview --theme`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum ThemeArg {
    /// Dark (the default).
    Dark,
    /// Light.
    Light,
}

/// `tornect host --capture`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum CaptureArg {
    /// The desktop, with this OS's capture backend.
    Desktop,
    /// A synthetic test card.
    TestCard,
}

impl From<CaptureArg> for tornect_session::Source {
    fn from(arg: CaptureArg) -> Self {
        match arg {
            CaptureArg::Desktop => Self::Desktop,
            CaptureArg::TestCard => Self::TestCard,
        }
    }
}

#[derive(Subcommand, Debug)]
enum ConfigAction {
    /// Print the effective configuration as TOML.
    Show,
    /// Print the configuration file path.
    Path,
    /// Write a default configuration file if none exists.
    Init {
        /// Overwrite an existing file.
        #[arg(long)]
        force: bool,
    },
}

fn main() -> anyhow::Result<()> {
    // Review finding E2-4: before anything can load a DLL by name, run-time
    // loads are restricted to the system directory (never the current
    // directory, `PATH` or this executable's folder).
    #[cfg(windows)]
    tornect_platform::restrict_dll_search()
        .context("restricting where Windows may load DLLs from")?;
    let cli = Cli::parse();
    let _log_guard = telemetry::init(LogOptions {
        filter: cli.log.clone(),
        file_dir: None,
        json: cli.json_logs,
    })?;

    let paths = match &cli.home {
        Some(dir) => {
            #[cfg(windows)]
            windows_home_allowed(dir)?;
            Paths::from_home(dir)
        }
        None => Paths::discover()?,
    };

    let Some(command) = cli.command else {
        return ui::run(
            &paths,
            ui::GuiOpts {
                source: tornect_session::Source::Desktop,
                host: true,
                bridges: cli.bridges,
                preview: false,
                page: None,
                theme: egui::Theme::Dark,
            },
        );
    };
    match command {
        Command::Gui {
            capture,
            no_host,
            preview,
            page,
            theme,
        } => ui::run(
            &paths,
            ui::GuiOpts {
                source: capture.into(),
                host: !no_host,
                bridges: cli.bridges,
                preview,
                page: page.map(Into::into),
                theme: match theme {
                    Some(ThemeArg::Light) => egui::Theme::Light,
                    Some(ThemeArg::Dark) | None => egui::Theme::Dark,
                },
            },
        ),
        Command::Id { json } => cmd_id(&paths, json),
        Command::RotateId { yes } => cmd_rotate_id(&paths, yes),
        Command::Paths => {
            for (name, dir) in paths.all() {
                println!("{name:>7}: {}", dir.display());
            }
            Ok(())
        }
        Command::Config { action } => cmd_config(&paths, action),
        Command::Doctor => cmd_doctor(&paths),
        Command::Host {
            once,
            pow,
            no_pow,
            capture,
        } => {
            let pow = match (pow, no_pow) {
                (true, _) => Some(true),
                (_, true) => Some(false),
                _ => None,
            };
            tor_cmd::host(&paths, once, pow, cli.bridges, capture.into())
        }
        Command::TorCheck => tor_cmd::tor_check(&paths, cli.bridges),
        Command::Ping { onion, count } => tor_cmd::ping(&paths, &onion, count, cli.bridges),
        Command::Connect {
            onion,
            pair_only,
            forget,
            pings,
            no_video,
        } => tor_cmd::connect(
            &paths,
            &onion,
            tor_cmd::ConnectOpts {
                pair_only,
                forget,
                pings,
                video: !no_video,
            },
            cli.bridges,
        ),
        Command::Unattended { action } => unattended::unattended(&paths, action),
        Command::Devices { json } => unattended::devices(&paths, json),
        Command::Panic => unattended::panic_now(&paths),
        Command::Service { action } => unattended::service(&paths, action),
        Command::Backup { action } => unattended::backup(&paths, action),
    }
}

/// Review finding E2-2: on Windows, Tornect's directories get no private
/// permissions of their own yet, so a `--home` or `TORNECT_HOME` is taken only
/// inside the user's profile folder, as the OS names it
/// (`tornect_platform::autostart::windows_home_ok`, the start-at-login task's
/// rule).
#[cfg(windows)]
fn windows_home_allowed(dir: &std::path::Path) -> anyhow::Result<()> {
    let home = std::path::absolute(dir).with_context(|| format!("resolving {}", dir.display()))?;
    let home = home
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("{} is not valid Unicode", home.display()))?;
    let profile = tornect_platform::user_profile().ok();
    let profile = profile.as_deref().and_then(std::path::Path::to_str);
    tornect_platform::autostart::windows_home_ok(home, profile).map_err(anyhow::Error::msg)
}

fn parse_bridge_mode(s: &str) -> Result<BridgeMode, String> {
    match s {
        "auto" => Ok(BridgeMode::Auto),
        "off" | "direct" => Ok(BridgeMode::Off),
        "obfs4" => Ok(BridgeMode::Obfs4),
        "snowflake" => Ok(BridgeMode::Snowflake),
        other => Err(format!("{other:?}: expected auto, off, obfs4 or snowflake")),
    }
}

fn open_store(paths: &Paths) -> anyhow::Result<FileSecretStore> {
    paths.ensure().context("creating Tornect directories")?;
    FileSecretStore::open(paths.keys_dir()).context("opening keystore")
}

fn cmd_id(paths: &Paths, json: bool) -> anyhow::Result<()> {
    let store = open_store(paths)?;
    let (host, created) = load_or_create_host_identity(&store)?;
    let (device, _) = load_or_create_device_identity(&store)?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "tornect_id": host.id().onion_address(),
                "device_id": device.id().to_string(),
                "device_fingerprint": device.id().fingerprint(),
                "created": created,
                "keystore": paths.keys_dir(),
            })
        );
    } else {
        if created {
            println!(
                "Generated a new Tornect ID (stored in {}).",
                paths.keys_dir().display()
            );
        }
        println!("Tornect ID : {}", host.id().onion_address());
        println!("           : {}", host.id().display_groups());
        println!(
            "Device ID  : {}  (fingerprint {})",
            device.id(),
            device.id().fingerprint()
        );
    }
    Ok(())
}

fn cmd_rotate_id(paths: &Paths, yes: bool) -> anyhow::Result<()> {
    if !yes {
        eprintln!(
            "This generates a NEW Tornect ID. Every paired device and unattended grant \
             stops working until re-paired. Re-run with --yes to confirm."
        );
        std::process::exit(2);
    }
    let store = open_store(paths)?;
    // Arti's keystore holds its own copy of the identity key, keys derived from
    // it and the service's intro-point state (tornect-signal `tor::identity`);
    // an invalidated identity must not stay recoverable there. Done before the
    // new seed is written, so a failure leaves the old identity whole instead of
    // half rotated.
    use tornect_core::SecretStore as _;
    if store.contains(keystore::HOST_IDENTITY_SEED)? {
        let (old, _) = load_or_create_host_identity(&store)?;
        let forgotten = tornect_signal::forget_identity(paths, &old.id()).with_context(|| {
            format!(
                "removing the old Tornect ID {} from the Tor keystore and state",
                old.id()
            )
        })?;
        if forgotten == tornect_signal::ForgottenIdentity::default() {
            eprintln!("the old ID had no Tor keys or service state on this machine");
        } else {
            eprintln!(
                "removed the old ID's Tor keys and service state ({} key(s){})",
                forgotten.keys_removed,
                if forgotten.state_removed {
                    ", intro-point state"
                } else {
                    ""
                }
            );
        }
    }
    let host = keystore::rotate_host_identity(&store)?;
    let log = tornect_core::session_log::SessionLog::new(paths.sessions_log());
    log.append(&tornect_core::session_log::SessionRecord::now(
        tornect_core::session_log::SessionEvent::HostIdRotated,
    ))?;
    println!("New Tornect ID: {}", host.id().onion_address());
    Ok(())
}

fn cmd_config(paths: &Paths, action: ConfigAction) -> anyhow::Result<()> {
    let path = paths.config_file();
    match action {
        ConfigAction::Path => println!("{}", path.display()),
        ConfigAction::Show => {
            let cfg = Config::load(&path)?;
            print!("{}", toml_pretty(&cfg)?);
        }
        ConfigAction::Init { force } => {
            if path.exists() && !force {
                anyhow::bail!(
                    "{} already exists (use --force to overwrite)",
                    path.display()
                );
            }
            Config::default().save(&path)?;
            println!("Wrote {}", path.display());
        }
    }
    Ok(())
}

fn toml_pretty(cfg: &Config) -> anyhow::Result<String> {
    // Reuse the same serializer the config file uses.
    let dir = std::env::temp_dir().join(format!("tornect-config-show-{}", std::process::id()));
    let file = dir.join("config.toml");
    cfg.save(&file)?;
    let text = std::fs::read_to_string(&file)?;
    let _ = std::fs::remove_dir_all(&dir);
    Ok(text)
}

fn cmd_doctor(paths: &Paths) -> anyhow::Result<()> {
    println!(
        "tornect {} ({} {})",
        tornect_core::VERSION,
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    println!("protocol version: {}", tornect_core::PROTOCOL_VERSION);
    #[cfg(target_os = "linux")]
    {
        let session = std::env::var("XDG_SESSION_TYPE").unwrap_or_else(|_| "unknown".into());
        let desktop = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_else(|_| "unknown".into());
        println!("session: {session} ({desktop})");
    }
    for line in tor_cmd::capture_lines(paths, &tornect_session::DesktopBackend::detect()) {
        println!("{line}");
    }
    println!("directories:");
    for (name, dir) in paths.all() {
        let state = if dir.is_dir() { "ok" } else { "missing" };
        println!("  {name:>7}: {} [{state}]", dir.display());
    }
    let cfg_path = paths.config_file();
    match Config::load(&cfg_path) {
        Ok(cfg) => println!(
            "config: {} [{}] device_name={:?} paranoid={} lan_only={}",
            cfg_path.display(),
            if cfg_path.exists() {
                "present"
            } else {
                "defaults"
            },
            cfg.general.device_name,
            cfg.network.paranoid,
            cfg.network.lan_only
        ),
        Err(e) => println!("config: {} [ERROR: {e}]", cfg_path.display()),
    }
    let tor = Config::load(&cfg_path).map(|c| c.tor).unwrap_or_default();
    let lyrebird = tornect_signal::tor::find_lyrebird(tor.pt_path.as_deref());
    println!(
        "tor: bridges={:?} last-worked={} lyrebird={} extra-bridge-lines={}",
        tor.bridges,
        tornect_signal::tor::last_good(paths).map_or("none".to_owned(), |r| r.to_string()),
        match &lyrebird {
            Ok(p) => p.display().to_string(),
            Err(why) => format!("UNAVAILABLE ({why}; obfs4/Snowflake cannot run)"),
        },
        tor.bridge_lines.len()
    );
    let store = FileSecretStore::open(paths.keys_dir())?;
    use tornect_core::SecretStore as _;
    let has_host = store.contains(keystore::HOST_IDENTITY_SEED)?;
    let has_dev = store.contains(keystore::DEVICE_IDENTITY_SEED)?;
    println!(
        "host identity: {}",
        if has_host {
            "present"
        } else {
            "not yet generated (run `tornect id`)"
        }
    );
    println!(
        "device identity: {}",
        if has_dev {
            "present"
        } else {
            "not yet generated"
        }
    );
    let log = tornect_core::session_log::SessionLog::new(paths.sessions_log());
    println!(
        "sessions.log: {} ({} records)",
        log.path().display(),
        log.read_all()?.len()
    );
    Ok(())
}
