//! `tornect` command-line entry point.
//!
//! Milestone 0 ships the identity/config commands; Milestone 1 adds `host` and
//! `ping` over the live Tor network; `connect`, `demo` and the graphical app
//! arrive with later milestones (`docs/PLAN.md` Part C).

#![forbid(unsafe_code)]
#![allow(clippy::print_stdout, clippy::print_stderr)]

mod tor_cmd;
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

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
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
    /// Publish this machine's Tornect ID as a Tor onion service and answer pings.
    ///
    /// Prints `Tornect ID: <onion>` as soon as the service is launched and
    /// `REACHABLE` once the address is published on the Tor network. Ctrl-C stops.
    Host {
        /// Exit after the first ping has been answered (scripted verification).
        #[arg(long)]
        once: bool,
        /// Force proof-of-work introduction defense on (default: config `tor.pow_defense`).
        #[arg(long, conflicts_with = "no_pow")]
        pow: bool,
        /// Force proof-of-work introduction defense off.
        #[arg(long, conflicts_with = "pow")]
        no_pow: bool,
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
    let cli = Cli::parse();
    let _log_guard = telemetry::init(LogOptions {
        filter: cli.log.clone(),
        file_dir: None,
        json: cli.json_logs,
    })?;

    let paths = match &cli.home {
        Some(dir) => Paths::from_home(dir),
        None => Paths::discover()?,
    };

    match cli.command {
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
        Command::Host { once, pow, no_pow } => {
            let pow = match (pow, no_pow) {
                (true, _) => Some(true),
                (_, true) => Some(false),
                _ => None,
            };
            tor_cmd::host(&paths, once, pow, cli.bridges)
        }
        Command::TorCheck => tor_cmd::tor_check(&paths, cli.bridges),
        Command::Ping { onion, count } => tor_cmd::ping(&paths, &onion, count, cli.bridges),
        Command::Unattended { action } => unattended::unattended(&paths, action),
        Command::Devices { json } => unattended::devices(&paths, json),
        Command::Panic => unattended::panic_now(&paths),
        Command::Service { action } => unattended::service(&paths, action),
        Command::Backup { action } => unattended::backup(&paths, action),
    }
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
        if session != "wayland" {
            println!(
                "  note: Tornect v1 targets Wayland (X11 capture is out of scope, docs/PLAN.md §B.5)"
            );
        }
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
        lyrebird.as_ref().map_or_else(
            || "NOT FOUND (obfs4/Snowflake unavailable; see tor.pt_path)".to_owned(),
            |p| p.display().to_string()
        ),
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
