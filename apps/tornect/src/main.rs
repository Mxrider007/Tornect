//! `tornect` entry point: the desktop window with no subcommand (or `tornect
//! gui`), and the command line.
//!
//! Milestone 0 ships the identity/config commands; Milestone 1 adds `host`,
//! `ping` and `connect` over the live Tor network; the vertical slice adds the
//! window (`ui`, decision D10's egui-everywhere fallback); the quality presets
//! add `demo --loopback --headless-stats`, the media pipeline measured in one
//! process (M3's loopback demo, with its packetizer and render, comes later:
//! `docs/PLAN.md` Part C).

#![forbid(unsafe_code)]
#![allow(clippy::print_stdout, clippy::print_stderr)]
// Windows: a window-subsystem program, so opening the window starts no
// console (Privacy U3-M1); the command line attaches to the console it was
// started from (`tornect_platform::attach_parent_console`).
#![cfg_attr(all(windows, not(test)), windows_subsystem = "windows")]

// `+crt-static` comes from `.cargo/config.toml`, and a `RUSTFLAGS` variable
// silently replaces it; a dynamically linked `tornect.exe` would then load
// libc++/libunwind through the DLL search order (SLICE-A1 A1-10).
#[cfg(all(windows, target_env = "gnu", not(target_feature = "crt-static")))]
compile_error!(
    "the Windows build must link the C runtime statically: build without RUSTFLAGS, \
     or add `-C target-feature=+crt-static` to it"
);

mod admin_helper;
mod demo_cmd;
mod diagnostics;
mod helper_cmd;
mod history;
mod host;
mod install_cmd;
mod prompt;
mod rotate;
mod secure_screen;
mod term_block;
#[cfg(test)]
mod test_support;
mod tor_cmd;
mod ua_client;
mod ui;
mod unattended;

use std::path::PathBuf;

use anyhow::Context as _;
use clap::{Parser, Subcommand};
use tornect_core::config::{BridgeMode, QualityPreset};
use tornect_core::invite::{self, IdProblem};
use tornect_core::keystore::{
    self, FileSecretStore, load_or_create_device_identity, load_or_create_host_identity,
};
use tornect_core::telemetry::{self, LogOptions};
use tornect_core::unattended::ipc::ShownLink;
use tornect_core::{Config, Paths};

#[derive(Parser, Debug)]
#[command(name = "tornect", version, about, long_about = None)]
struct Cli {
    /// Put all Tornect state under this directory (env: TORNECT_HOME).
    #[arg(long, global = true, env = tornect_core::paths::HOME_ENV, value_name = "DIR")]
    home: Option<PathBuf>,

    /// Log filter, e.g. `debug` or `tornect_signal=trace` (env: TORNECT_LOG).
    /// Under every filter the fields of a log line that name a device, a
    /// person or a computer read `<redacted>`; `--log-identifiers` writes
    /// them. Message and error texts are written as they are: they can quote
    /// a path, or a line of a file that holds a Tornect ID. With --json-logs,
    /// warnings and errors are written in full.
    #[arg(long, global = true, value_name = "FILTER")]
    log: Option<String>,

    /// Write names, labels, Tornect IDs and fingerprints into the log as
    /// they are, e.g. for a bug report you read before sending (env:
    /// TORNECT_LOG_IDENTIFIERS=1). Without it they are redacted.
    #[arg(long, global = true)]
    log_identifiers: bool,

    /// Emit JSON log lines on stderr. Below WARN, a line with a field that
    /// names a device, a person or a computer is left out unless
    /// --log-identifiers is given; warnings and errors are written in full.
    #[arg(long, global = true)]
    json_logs: bool,

    /// Print the lines the live-check scripts read on stdout: the name of
    /// the host a session views and this computer's Tornect ID (env:
    /// TORNECT_EVIDENCE=1). Without it the window prints session ids only,
    /// and `tornect host` prints its Tornect ID only to a terminal.
    #[arg(long, global = true)]
    evidence: bool,

    /// How to reach Tor: `auto` (direct, then obfs4 bridges, then Snowflake),
    /// `off` (direct only), `obfs4` or `snowflake`. Default: config `tor.bridges`.
    #[arg(long, global = true, value_name = "MODE", value_parser = parse_bridge_mode)]
    bridges: Option<BridgeMode>,

    /// Start the window minimised, as the start at sign-in does: unattended
    /// sessions wait until its sharing indicator has been shown, and a
    /// request raises the window. If Tornect already runs for this home, end
    /// at once. Takes no subcommand.
    #[arg(long)]
    background: bool,

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
        /// What a session shares: `desktop`, `test-card` or `test-screens`
        /// (see `host`).
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
        /// With --preview: an empty address book (a first run).
        #[arg(long, hide = true, requires = "preview")]
        empty: bool,
        /// With --preview --page: one host sheet of this kind on screen.
        #[arg(long, hide = true, value_enum, requires = "page")]
        sheet: Option<SheetArg>,
    },
    /// Show this machine's Tornect ID (its onion v3 address), creating it on first run.
    Id {
        /// Print machine-readable JSON.
        #[arg(long)]
        json: bool,
        /// Print only an invitation to share: this ID, its tornect:// link and
        /// where to get Tornect.
        #[arg(long, conflicts_with = "json")]
        invitation: bool,
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
    /// Prints `Tornect ID: <onion>` as soon as the service is launched (on a
    /// terminal, or with --evidence) and `REACHABLE` once the address is
    /// published on the Tor network. Ctrl-C stops hosting and ends every
    /// session.
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
        /// Windows), `test-card` (a synthetic picture; the viewer's input
        /// goes nowhere) or `test-screens` (two synthetic screens side by
        /// side, 1280x720 (main) and 1024x768, for switching between; the
        /// viewer's input goes nowhere).
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
    /// Install Tornect on this computer, after your password: on Linux for
    /// you, in ~/.local/bin with a menu entry; on Windows in Program Files.
    /// Then choose whether Tornect starts when you sign in. Your pairings and
    /// grants stay where they are.
    Install,
    /// Remove what `tornect install` set up, and the start at sign-in
    /// whichever copy it runs, after your password. Your pairings and grants
    /// stay.
    Uninstall,
    /// Reach the Tor network (direct, obfs4 bridges or Snowflake, per `--bridges`)
    /// and report which transport worked.
    TorCheck,
    /// Open a tornect:// link: bring Tornect's window forward, or open a
    /// connect-only window, with the link's ID in the connect field. It never
    /// connects by itself.
    OpenLink {
        /// The link, `tornect://<ID>`, given after `--`.
        #[arg(value_name = "LINK")]
        link: std::ffi::OsString,
    },
    /// Connect to a host by Tornect ID over Tor and measure round-trip times.
    ///
    /// Uses this instance's own Tor state; run it under a different TORNECT_HOME
    /// than the host when both live on one machine.
    Ping {
        /// The host's Tornect ID (56 characters, with or without `.onion`), its
        /// tornect:// link, or a whole invitation in quotes.
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
    /// This command shows no picture: it decodes and counts the pictures (the
    /// window, `tornect` without a subcommand, shows them). Uses this
    /// instance's own Tor state; run it under a different TORNECT_HOME
    /// than the host when both live on one machine.
    Connect {
        /// The host's Tornect ID (56 characters, with or without `.onion`), its
        /// tornect:// link, or a whole invitation in quotes.
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
        /// The picture quality to ask for: best-quality, balanced or
        /// best-performance (default: the viewer's quality in config.toml,
        /// itself balanced). The host fits it to its own limits.
        #[arg(long, value_name = "PRESET")]
        quality: Option<QualityPreset>,
        /// The host's screen to show: 1 to 16, or all (every screen at once,
        /// where the host offers it). Asked for as soon as the host lists its
        /// screens; a host that lists none is not asked.
        #[arg(
            long,
            value_name = "SCREEN",
            value_parser = parse_screen,
            conflicts_with_all = ["pair_only", "no_video"]
        )]
        screen: Option<u8>,
        /// Connect without asking: this device's unattended access at the host
        /// (a paired host whose owner gave it). The password is asked on this
        /// terminal, never taken from the command line or the environment; one
        /// attempt per run, never repeated. A password remembered with
        /// --remember is used without asking.
        #[arg(long, conflicts_with_all = ["pair_only", "forget"])]
        unattended: bool,
        /// With --unattended: view only this time.
        #[arg(long, requires = "unattended")]
        view_only: bool,
        /// With --unattended: keep the password in this computer's keychain once
        /// it worked, if the host's answer allows it: a password that can reach
        /// administrator access there, or that the host did not rule out, is
        /// never kept. Any program running as you can read it there; on Linux
        /// it stays on this account until a restart, or for a few days after
        /// you sign out. Refused without a usable keychain, and for
        /// administrator access.
        #[arg(long, requires = "unattended")]
        remember: bool,
        /// With --unattended: ask for administrator access (with control only).
        /// The host gives it only if this device's grant carries it; otherwise
        /// the session goes on without it.
        #[arg(long, requires = "unattended", conflicts_with = "view_only")]
        administrator: bool,
        /// Never accepted: a password on the command line is refused, with the
        /// reason.
        #[arg(long, hide = true, value_name = "PASSWORD", num_args = 0..=1)]
        password: Option<Option<String>>,
    },
    /// Measure the media pipeline on this computer: a synthetic desktop sent
    /// through the real host and viewer in one process, with no Tor, no
    /// network and no window. Prints the stage times once a second, then a
    /// summary read against the latency targets of the plan (§B.7). Only
    /// `--loopback --headless-stats` is available; build with `--release`
    /// for numbers worth recording.
    Demo {
        /// Host and viewer in this process, over an in-memory pipe.
        #[arg(long)]
        loopback: bool,
        /// Print the numbers; show no picture.
        #[arg(long)]
        headless_stats: bool,
        /// The synthetic desktop's size, WIDTHxHEIGHT.
        #[arg(long, value_name = "WxH", default_value = "1920x1080", value_parser = demo_cmd::parse_size)]
        size: (u32, u32),
        /// The synthetic desktop's frame rate: it delivers at that rate, as
        /// a desktop does; the encoder keeps to the preset's.
        #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u32).range(1..=240))]
        fps: u32,
        /// The picture quality the viewer asks for: best-quality, balanced or
        /// best-performance.
        #[arg(long, value_name = "PRESET", default_value_t = QualityPreset::Balanced)]
        quality: QualityPreset,
        /// How long to measure, in seconds.
        #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u32).range(1..=3600))]
        seconds: u32,
        /// The encoder's threads: 1, 0 for automatic (one less than the
        /// cores, 1 to 4), or 2 to 4.
        #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u8).range(0..=4))]
        threads: u8,
    },
    /// Send one admin command to a paired host on this device's unattended
    /// access there (its password asked on this terminal; one attempt, after a
    /// confirmation): revoke this device there, end this device's session
    /// there, turn unattended access off there, or unlock another of your
    /// devices there. The last two work only from a "My machines" access with
    /// control; the host decides and answers.
    Admin {
        /// The host's Tornect ID (56 characters, with or without `.onion`), its
        /// tornect:// link, or a whole invitation in quotes.
        onion: String,
        /// What to do.
        #[arg(value_enum)]
        action: AdminArg,
        /// With `unlock`: the device ID of the device to unlock.
        #[arg(long, value_name = "DEVICE_ID", required_if_eq("action", "unlock"))]
        device: Option<String>,
        /// Never accepted: a password on the command line is refused, with the
        /// reason.
        #[arg(long, hide = true, value_name = "PASSWORD", num_args = 0..=1)]
        password: Option<Option<String>>,
    },
}

/// `tornect admin <id> <action>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum AdminArg {
    /// Revoke this device's unattended access at the host.
    RevokeThisDevice,
    /// End this device's live session at the host.
    EndSession,
    /// Turn unattended access off at the host.
    TurnUnattendedOff,
    /// Reset the wrong-password lock of another of your devices at the host.
    Unlock,
}

impl From<AdminArg> for ua_client::AdminAction {
    fn from(arg: AdminArg) -> Self {
        match arg {
            AdminArg::RevokeThisDevice => Self::RevokeThisDevice,
            AdminArg::EndSession => Self::EndSession,
            AdminArg::TurnUnattendedOff => Self::TurnOff,
            AdminArg::Unlock => Self::Unlock,
        }
    }
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

/// `tornect gui --preview --page … --sheet`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum SheetArg {
    /// A new device asks to pair.
    New,
    /// A paired device asks to pair again.
    Pinned,
    /// A new device that looks like a saved one.
    Alarm,
    /// A paired device asks for a session.
    Session,
    /// The session sheet with Linux's levels (§B.2.1).
    SessionLinux,
    /// The session sheet of an invented Windows host with UAC off.
    SessionAdmin,
    /// That sheet's administrator confirmation.
    AdminConfirm,
    /// An installed Windows host, UAC on, as this build offers it.
    SessionWindows,
    /// That row with the administrator helper: four answers.
    SessionFour,
    /// The four-answer sheet after its Windows prompt failed.
    AdminNotGiven,
    /// An administrator account that elevates without prompting.
    SessionNoPrompt,
    /// That row with the administrator helper, a device paired moments before.
    NoPromptHelper,
    /// That sheet's Tornect confirmation.
    NoPromptConfirm,
    /// A pairing and a session question at once.
    TwoOpen,
    /// The connect stepper: reaching the computer.
    StageReaching,
    /// The connect stepper: pairing, the code question open.
    StagePairing,
    /// The connect stepper: waiting for approval.
    StageAsking,
    /// The connect stepper: connected.
    StageLive,
    /// The connect stepper: the computer could not be reached.
    StageUnreachable,
    /// The connect stepper: the person there said no.
    StageDenied,
    /// The connect stepper: the codes differed.
    StageCodesDiffer,
    /// A saved computer where connecting without asking worked.
    UaCard,
    /// The password prompt of an unattended connect.
    UaPrompt,
    /// The connect stepper: an unattended connect refused.
    UaRefused,
    /// The connect stepper: an unattended session live.
    UaLive,
    /// History off: Home's first-run line, and the Recent tab.
    HistoryOff,
    /// Forget's confirmation on the first saved computer.
    ForgetAsk,
    /// The Unlock confirmation with the typed device's words.
    UaUnlock,
    /// The connect field filled from a link, with its note.
    LinkFilled,
    /// The stream window's Quality menu, a pick on its way.
    ViewerQuality,
    /// The stream window's details with the Quality and Timing rows.
    ViewerDetails,
}

impl From<SheetArg> for ui::preview::Sheet {
    fn from(arg: SheetArg) -> Self {
        match arg {
            SheetArg::New => Self::New,
            SheetArg::Pinned => Self::Pinned,
            SheetArg::Alarm => Self::Alarm,
            SheetArg::Session => Self::Session,
            SheetArg::SessionLinux => Self::SessionLinux,
            SheetArg::SessionAdmin => Self::SessionAdmin,
            SheetArg::AdminConfirm => Self::AdminConfirm,
            SheetArg::SessionWindows => Self::SessionWindows,
            SheetArg::SessionFour => Self::SessionFour,
            SheetArg::AdminNotGiven => Self::AdminNotGiven,
            SheetArg::SessionNoPrompt => Self::SessionNoPrompt,
            SheetArg::NoPromptHelper => Self::NoPromptHelper,
            SheetArg::NoPromptConfirm => Self::NoPromptConfirm,
            SheetArg::TwoOpen => Self::TwoOpen,
            SheetArg::StageReaching => Self::StageReaching,
            SheetArg::StagePairing => Self::StagePairing,
            SheetArg::StageAsking => Self::StageAsking,
            SheetArg::StageLive => Self::StageLive,
            SheetArg::StageUnreachable => Self::StageUnreachable,
            SheetArg::StageDenied => Self::StageDenied,
            SheetArg::StageCodesDiffer => Self::StageCodesDiffer,
            SheetArg::UaCard => Self::UaCard,
            SheetArg::UaPrompt => Self::UaPrompt,
            SheetArg::UaRefused => Self::UaRefused,
            SheetArg::UaLive => Self::UaLive,
            SheetArg::HistoryOff => Self::HistoryOff,
            SheetArg::ForgetAsk => Self::ForgetAsk,
            SheetArg::UaUnlock => Self::UaUnlock,
            SheetArg::LinkFilled => Self::LinkFilled,
            SheetArg::ViewerQuality => Self::ViewerQuality,
            SheetArg::ViewerDetails => Self::ViewerDetails,
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
    /// Two synthetic screens side by side, to switch between.
    TestScreens,
}

/// `tornect connect --screen`: a screen's number, `1` to `16`, or `all`
/// (any case) for every screen at once, which the media stream calls 0
/// ([`tornect_proto::ALL_MONITORS`]).
fn parse_screen(given: &str) -> Result<u8, String> {
    if given.eq_ignore_ascii_case("all") {
        return Ok(tornect_proto::ALL_MONITORS);
    }
    given
        .parse::<u8>()
        .ok()
        .filter(|&n| (1..=tornect_proto::MAX_MONITORS).contains(&usize::from(n)))
        .ok_or_else(|| "a screen is a number from 1 to 16, or all".to_owned())
}

impl From<CaptureArg> for tornect_session::Source {
    fn from(arg: CaptureArg) -> Self {
        match arg {
            CaptureArg::Desktop => Self::Desktop,
            CaptureArg::TestCard => Self::TestCard,
            CaptureArg::TestScreens => Self::TestScreens,
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

/// An internal step of the installed copy (§B.1.1), run elevated by
/// `tornect install` and `tornect uninstall` on Windows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InternalStep {
    /// `tornect install-entry`: write Tornect's uninstall entry.
    InstallEntry,
    /// `tornect remove-at-restart`: mark this copy and its folder for
    /// removal at the next restart.
    RemoveAtRestart,
}

/// The internal step this program's whole command line, `args`, asks for:
/// exactly the program and the step's name, nothing before or after it and
/// in that case only; anything else is not a step (and the parser refuses
/// it).
fn internal_step(args: &[std::ffi::OsString]) -> Option<InternalStep> {
    match args {
        [_, step] if step == tornect_platform::install::ENTRY_STEP_ARGUMENT => {
            Some(InternalStep::InstallEntry)
        }
        [_, step] if step == tornect_platform::install::RESTART_STEP_ARGUMENT => {
            Some(InternalStep::RemoveAtRestart)
        }
        _ => None,
    }
}

/// Run `step`: exit code 0 when it was done, 1 when it was refused or
/// failed (it runs hidden: no text is seen). It starts no runtime, takes no
/// lock, opens no store, logs nothing and reads no environment variable and
/// no other argument. Not on this system: exit code 2.
fn run_internal_step(step: InternalStep) -> i32 {
    #[cfg(windows)]
    {
        use tornect_platform::win_install::{
            RealWindows, delete_in_folder, mark_for_removal_at_restart, own_path,
            write_uninstall_entry,
        };
        let sys = RealWindows::of_this_computer();
        let done = own_path().and_then(|own| match step {
            InternalStep::InstallEntry => {
                tornect_platform::install::write_own_entry(&sys, &own, &write_uninstall_entry)
            }
            InternalStep::RemoveAtRestart => {
                tornect_platform::install::mark_own_folder_for_restart(
                    &sys,
                    &own,
                    &delete_in_folder,
                    &mark_for_removal_at_restart,
                )
            }
        });
        i32::from(done.is_err())
    }
    #[cfg(not(windows))]
    {
        let _ = step;
        2
    }
}

fn main() -> anyhow::Result<()> {
    // Review finding E2-4: before anything can load a DLL by name, run-time
    // loads are restricted to the system directory (never the current
    // directory, `PATH` or this executable's folder).
    #[cfg(windows)]
    tornect_platform::restrict_dll_search()
        .context("restricting where Windows may load DLLs from")?;
    // The administrator helper (§B.8.7.5) runs before anything reads the
    // environment, a config or a file (H2): not the parser (`--home` reads
    // `TORNECT_HOME`), not the log, not the paths.
    if std::env::args_os()
        .nth(1)
        .is_some_and(|a| a == "input-helper")
    {
        std::process::exit(helper_cmd::run(
            &std::env::args_os().skip(2).collect::<Vec<_>>(),
        ));
    }
    // The installed copy's internal steps, the same way: before anything
    // reads the environment, a config or a file, and with no other argument.
    if let Some(step) = internal_step(&std::env::args_os().collect::<Vec<_>>()) {
        std::process::exit(run_internal_step(step));
    }
    // Windows: with arguments, print to the console this was started from
    // (a window-subsystem program has none of its own); without, the window
    // opens and no console appears.
    #[cfg(windows)]
    if std::env::args_os().len() > 1 {
        tornect_platform::attach_parent_console();
    }
    let cli = Cli::parse();
    host::opt_in_evidence(cli.evidence);
    admin_helper::opt_in_log_identifiers(cli.log_identifiers);
    let _log_guard = telemetry::init(LogOptions {
        filter: cli.log.clone(),
        file_dir: None,
        json: cli.json_logs,
        identifiers: cli.log_identifiers,
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
        if cli.background {
            // The start at sign-in (§B.1.1): with a Tornect host running here
            // it ends at once and asks that host nothing, so a window someone
            // minimised stays minimised.
            if background_already_running(&paths) {
                return Ok(());
            }
        } else if second_launch_shown(&paths, None) {
            // A second launch raises the running window instead (§B.1.1).
            return Ok(());
        }
        return ui::run(
            &paths,
            ui::GuiOpts {
                source: tornect_session::Source::Desktop,
                host: true,
                bridges: cli.bridges,
                preview: false,
                page: None,
                empty: false,
                sheet: None,
                theme: egui::Theme::Dark,
                link: None,
            },
            cli.background,
        );
    };
    anyhow::ensure!(
        !cli.background,
        "--background starts the window minimised; it takes no subcommand"
    );
    match command {
        Command::Gui {
            capture,
            no_host,
            preview,
            page,
            theme,
            empty,
            sheet,
        } => {
            if !preview && !no_host && second_launch_shown(&paths, None) {
                return Ok(());
            }
            ui::run(
                &paths,
                ui::GuiOpts {
                    source: capture.into(),
                    host: !no_host,
                    bridges: cli.bridges,
                    preview,
                    page: page.map(Into::into),
                    empty,
                    sheet: sheet.map(Into::into),
                    theme: match theme {
                        Some(ThemeArg::Light) => egui::Theme::Light,
                        Some(ThemeArg::Dark) | None => egui::Theme::Dark,
                    },
                    link: None,
                },
                false,
            )
        }
        Command::Id { json, invitation } => cmd_id(&paths, json, invitation),
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
        Command::OpenLink { link } => open_link(&paths, cli.bridges, &link),
        Command::Ping { onion, count } => tor_cmd::ping(&paths, &onion, count, cli.bridges),
        Command::Connect {
            onion,
            pair_only,
            forget,
            pings,
            no_video,
            quality,
            screen,
            unattended,
            view_only,
            remember,
            administrator,
            password,
        } => {
            ua_client::refuse_password_sources(password.is_some(), std::env::vars_os())?;
            tor_cmd::connect(
                &paths,
                &onion,
                tor_cmd::ConnectOpts {
                    pair_only,
                    forget,
                    pings,
                    video: !no_video,
                    quality,
                    screen,
                    unattended: unattended.then_some(tor_cmd::UnattendedOpts {
                        view_only,
                        remember,
                        administrator,
                    }),
                },
                cli.bridges,
            )
        }
        Command::Admin {
            onion,
            action,
            device,
            password,
        } => {
            ua_client::refuse_password_sources(password.is_some(), std::env::vars_os())?;
            tor_cmd::admin(
                &paths,
                &onion,
                action.into(),
                device.as_deref(),
                cli.bridges,
            )
        }
        Command::Demo {
            loopback,
            headless_stats,
            size,
            fps,
            quality,
            seconds,
            threads,
        } => {
            if !(loopback && headless_stats) {
                eprintln!("{}", demo_cmd::ONLY_LOOPBACK);
                std::process::exit(2);
            }
            demo_cmd::run(demo_cmd::DemoOpts {
                size,
                fps,
                quality,
                run_for: std::time::Duration::from_secs(u64::from(seconds)),
                threads,
            })
        }
        Command::Unattended { action } => unattended::unattended(&paths, action),
        Command::Devices { json } => unattended::devices(&paths, json),
        Command::Panic => unattended::panic_now(&paths),
        Command::Service { action } => unattended::service(&paths, action),
        Command::Backup { action } => unattended::backup(&paths, action),
        Command::Install => install_cmd::install(&paths),
        Command::Uninstall => install_cmd::uninstall(&paths),
    }
}

/// How long a second window launch waits for the running Tornect to raise its
/// window (§B.1.1); past it, the window opens as before. `ipc::request` alone
/// waits up to its 150 s.
const SHOW_WAIT: std::time::Duration = std::time::Duration::from_secs(3);

/// A second window launch (§B.1.1): when a Tornect host runs for these
/// directories, ask it to raise its window (`IpcOp::Show`), with the `link`
/// a link launch opened (design `invite` §2.4); `true` when it did, and this
/// launch ends there. Nothing running, a refusal (a host with no window, or
/// one without its store), an error, or no answer within [`SHOW_WAIT`] is
/// `false`: the window opens as it always did.
async fn shown_by_the_running_host(paths: &Paths, link: Option<ShownLink>) -> bool {
    if host::HostLock::holder(paths).is_none() {
        return false;
    }
    let req = tornect_core::unattended::ipc::IpcRequest {
        id: 1,
        op: tornect_core::unattended::ipc::IpcOp::Show { link },
    };
    matches!(
        tokio::time::timeout(SHOW_WAIT, tornect_platform::ipc::request(&paths.state_dir, &req)).await,
        Ok(Ok(resp)) if resp.ok
    )
}

/// A `--background` launch (the start at sign-in, §B.1.1) that finds a
/// Tornect host running for these directories: it ends at once, with exit
/// code 0, and sends that host nothing (no `Show`).
fn background_already_running(paths: &Paths) -> bool {
    host::HostLock::holder(paths).is_some()
}

/// [`shown_by_the_running_host`], on a runtime of its own (before the
/// window's).
fn second_launch_shown(paths: &Paths, link: Option<ShownLink>) -> bool {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .is_ok_and(|runtime| runtime.block_on(shown_by_the_running_host(paths, link)))
}

/// `tornect open-link -- <link>`, what the OS runs for an opened `tornect:`
/// link (design `invite` §2.4). The running window is raised with the link;
/// with none (or a host without a window) a connect-only window opens with
/// it. Either way the link at most fills the connect field: nothing
/// connects, pairs or answers, and a link never starts hosting (L-1, L-5).
fn open_link(
    paths: &Paths,
    bridges: Option<BridgeMode>,
    link: &std::ffi::OsStr,
) -> anyhow::Result<()> {
    let raised = |shown| second_launch_shown(paths, Some(shown));
    match link_launch(shown_link(link), raised, bridges) {
        Some(opts) => ui::run(paths, opts, false),
        None => Ok(()),
    }
}

/// What a link launch does with what it read of its link, `shown` (design
/// `invite` §2.4, L-5): first `raised`, the running window asked to raise
/// itself with it; when that took it, nothing more (`None`). Otherwise the
/// window to open, always [`link_window_opts`]'s connect-only one.
fn link_launch(
    shown: ShownLink,
    raised: impl FnOnce(ShownLink) -> bool,
    bridges: Option<BridgeMode>,
) -> Option<ui::GuiOpts> {
    (!raised(shown)).then(|| link_window_opts(bridges, shown))
}

/// What the window gets of an opened link: its ID, or the word that it was
/// refused, so the window can say why nothing was filled in (there is no
/// console when the OS starts this). A refusal is logged by its static
/// problem name only, never the link (L-7), and told on stderr for a
/// terminal.
fn shown_link(link: &std::ffi::OsStr) -> ShownLink {
    match read_link(link) {
        Ok(id) => ShownLink::Fill(id),
        Err(problem) => {
            tracing::info!(problem = problem.name(), "a tornect: link was refused");
            eprintln!("That link was not opened: {problem}.");
            ShownLink::Refused
        }
    }
}

/// The strict link reading of design `invite` §4.1; text that is not UTF-8
/// is no link.
fn read_link(link: &std::ffi::OsStr) -> Result<tornect_core::TornectId, IdProblem> {
    link.to_str()
        .ok_or(IdProblem::NotALink)
        .and_then(invite::parse_link)
}

/// The window a link opens when no Tornect window runs here: connect-only
/// (L-5), so a web page that opens a link never starts hosting, the onion
/// service or unattended access; it takes no host lock and serves no IPC.
fn link_window_opts(bridges: Option<BridgeMode>, shown: ShownLink) -> ui::GuiOpts {
    ui::GuiOpts {
        source: tornect_session::Source::Desktop,
        host: false,
        bridges,
        preview: false,
        page: None,
        empty: false,
        sheet: None,
        theme: egui::Theme::Dark,
        link: Some(shown),
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

fn cmd_id(paths: &Paths, json: bool, invitation: bool) -> anyhow::Result<()> {
    let store = open_store(paths)?;
    let (host, created) = load_or_create_host_identity(&store)?;
    let (device, _) = load_or_create_device_identity(&store)?;
    let shown = if invitation {
        IdShown::Invitation
    } else if json {
        IdShown::Json
    } else {
        IdShown::Lines
    };
    println!(
        "{}",
        id_output(shown, &host.id(), &device.id(), created, &paths.keys_dir())
    );
    Ok(())
}

/// Which form of `tornect id` is printed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdShown {
    /// The lines of [`id_lines`], after a word on a new ID.
    Lines,
    /// `--json`: [`id_json`].
    Json,
    /// `--invitation`: the invitation alone (design `invite` §2.5).
    Invitation,
}

/// What `tornect id` prints, without the final newline.
fn id_output(
    shown: IdShown,
    id: &tornect_core::TornectId,
    device: &tornect_core::DeviceId,
    created: bool,
    keystore: &std::path::Path,
) -> String {
    match shown {
        IdShown::Invitation => invite::invitation(id),
        IdShown::Json => id_json(id, device, created, keystore).to_string(),
        IdShown::Lines => {
            let generated = created.then(|| {
                format!(
                    "Generated a new Tornect ID (stored in {}).",
                    keystore.display()
                )
            });
            generated
                .into_iter()
                .chain(id_lines(id, device))
                .collect::<Vec<_>>()
                .join("\n")
        }
    }
}

/// `tornect id`'s lines: the ID, its groups, its link (design `invite`
/// §2.5) and this device's ID.
fn id_lines(id: &tornect_core::TornectId, device: &tornect_core::DeviceId) -> [String; 4] {
    [
        format!("Tornect ID : {}", id.onion_address()),
        format!("           : {}", id.display_groups()),
        format!("Link       : {}", invite::link(id)),
        format!(
            "Device ID  : {device}  (fingerprint {})",
            device.fingerprint()
        ),
    ]
}

/// `tornect id --json`.
fn id_json(
    id: &tornect_core::TornectId,
    device: &tornect_core::DeviceId,
    created: bool,
    keystore: &std::path::Path,
) -> serde_json::Value {
    serde_json::json!({
        "tornect_id": id.onion_address(),
        "link": invite::link(id),
        "device_id": device.to_string(),
        "device_fingerprint": device.fingerprint(),
        "created": created,
        "keystore": keystore,
    })
}

/// Why `tornect rotate-id` refuses beside a running host: the window or
/// `tornect host` holds the unattended store, which the rotation wipes first.
const ROTATE_NEEDS_TORNECT_CLOSED: &str = "a running Tornect holds unattended access here; close \
     its window (or press Ctrl-C in its terminal) and run tornect rotate-id --yes again, or use \
     Rotate ID in the window's Settings, Security";

fn cmd_rotate_id(paths: &Paths, yes: bool) -> anyhow::Result<()> {
    if !yes {
        eprintln!(
            "This generates a NEW Tornect ID. Every paired device and unattended grant \
             stops working until re-paired. Re-run with --yes to confirm."
        );
        std::process::exit(2);
    }
    // Everything unattended is wiped through the guard, opened as the offline
    // command line opens it: refused while a host holds the store.
    let ctx = match unattended::offline_context(paths) {
        Ok(ctx) => ctx,
        Err(e)
            if matches!(
                e.downcast_ref::<tornect_core::unattended::store::StoreError>(),
                Some(tornect_core::unattended::store::StoreError::Locked(_))
            ) =>
        {
            anyhow::bail!(ROTATE_NEEDS_TORNECT_CLOSED)
        }
        Err(e) => return Err(e),
    };
    let store = open_store(paths)?;
    use tornect_core::SecretStore as _;
    // The unattended passwords this computer remembers go with the old ID
    // (§B.8.9.1): a new start keeps none of them.
    let saved = if store.contains(keystore::DEVICE_IDENTITY_SEED)? {
        let (device, _) = load_or_create_device_identity(&store)?;
        Some(ua_client::system_passwords(&device))
    } else {
        None
    };
    let rotated = rotate::rotate_id(
        paths,
        &ctx.guard,
        tornect_core::session_log::Actor::Cli,
        &store,
        saved.as_ref(),
    )?;
    if rotated.grants > 0 {
        eprintln!("removed unattended access for {} device(s)", rotated.grants);
    }
    let forgotten = rotated.forgotten;
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
    match rotated.passwords {
        Ok(0) => {}
        Ok(n) => eprintln!("deleted {n} remembered unattended password(s) from the keychain"),
        Err(e) => eprintln!("the remembered unattended passwords could not all be deleted: {e:#}"),
    }
    println!("New Tornect ID: {}", rotated.id.onion_address());
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
    let desktop = tornect_session::DesktopBackend::detect();
    for line in tor_cmd::capture_lines(paths, &desktop) {
        println!("{line}");
    }
    if let Some(line) = tor_cmd::screens_line(&desktop) {
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use std::path::PathBuf;

    use clap::{CommandFactory as _, Parser as _};
    use tornect_core::config::BridgeMode;
    use tornect_core::unattended::ipc::{IpcRequest, IpcResponse, ShownLink};

    const ID: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwd";

    /// The monitors design §2: `tornect connect <id> --screen N` takes a
    /// screen's number from 1 to 16, or `all` (the media stream's 0), and
    /// refuses anything else, naming the range; it asks for a picture, so
    /// it does not go with `--no-video` or `--pair-only`.
    #[test]
    fn connect_takes_a_screen_by_number_or_all() {
        let parse = |args: &[&str]| {
            super::Cli::try_parse_from(["tornect", "connect", ID].iter().chain(args))
        };
        let screen_of = |args: &[&str]| {
            let Some(super::Command::Connect { screen, .. }) = parse(args).unwrap().command else {
                panic!("not connect");
            };
            screen
        };
        assert_eq!(screen_of(&[]), None, "nothing is asked then");
        assert_eq!(screen_of(&["--screen", "2"]), Some(2));
        assert_eq!(screen_of(&["--screen=1"]), Some(1));
        assert_eq!(screen_of(&["--screen", "16"]), Some(16));
        for all in ["all", "All", "ALL"] {
            assert_eq!(
                screen_of(&["--screen", all]),
                Some(tornect_proto::ALL_MONITORS)
            );
        }
        for wrong in ["0", "17", "256", "-1", "two", "", "2.5", "1,2", " 2"] {
            let given = format!("--screen={wrong}");
            let err = parse(&[&given]).unwrap_err().to_string();
            assert!(
                err.contains("a screen is a number from 1 to 16, or all"),
                "{wrong:?}: {err}"
            );
        }
        for alone in [["--no-video"], ["--pair-only"]] {
            let args = [alone[0], "--screen", "2"];
            let err = parse(&args).unwrap_err();
            assert_eq!(
                err.kind(),
                clap::error::ErrorKind::ArgumentConflict,
                "{args:?}"
            );
        }
        let help = super::Cli::command()
            .find_subcommand_mut("connect")
            .unwrap()
            .render_long_help()
            .to_string();
        assert!(help.contains("--screen <SCREEN>"), "{help}");
        assert!(help.contains("1 to 16, or all"), "{help}");
    }

    /// The monitors design §2: `--capture test-screens` on `host` and `gui`
    /// shares the session layer's two synthetic screens.
    #[test]
    fn host_and_gui_share_the_test_screens() {
        for command in ["host", "gui"] {
            let cli = super::Cli::try_parse_from(["tornect", command, "--capture", "test-screens"])
                .unwrap();
            let capture = match cli.command {
                Some(
                    super::Command::Host { capture, .. } | super::Command::Gui { capture, .. },
                ) => capture,
                other => panic!("{command}: {other:?}"),
            };
            assert_eq!(capture, super::CaptureArg::TestScreens, "{command}");
            assert!(matches!(
                tornect_session::Source::from(capture),
                tornect_session::Source::TestScreens
            ));
        }
        let help = super::Cli::command()
            .find_subcommand_mut("host")
            .unwrap()
            .render_long_help()
            .to_string();
        assert!(help.contains("test-screens"), "{help}");
    }

    /// The quality design §3.5: `tornect connect <id> --quality P` takes the
    /// three presets by their config names and nothing else (the refusal
    /// names them); without it the session asks for `[viewer] quality`.
    #[test]
    fn connect_takes_a_quality_preset_by_its_name() {
        use tornect_core::config::QualityPreset;
        let parse = |args: &[&str]| {
            super::Cli::try_parse_from(["tornect", "connect", ID].iter().chain(args))
        };
        let quality_of = |args: &[&str]| {
            let Some(super::Command::Connect { quality, .. }) = parse(args).unwrap().command else {
                panic!("not connect");
            };
            quality
        };
        assert_eq!(quality_of(&[]), None, "the config's value then");
        for preset in QualityPreset::ALL {
            assert_eq!(quality_of(&["--quality", preset.as_str()]), Some(preset));
        }
        assert_eq!(
            quality_of(&["--unattended", "--quality=best-performance"]),
            Some(QualityPreset::BestPerformance)
        );
        for wrong in ["fast", "Balanced", "", "speed"] {
            let err = parse(&["--quality", wrong]).unwrap_err().to_string();
            assert!(
                err.contains("best-quality") && err.contains("best-performance"),
                "{wrong:?}: {err}"
            );
        }
        let help = super::Cli::command()
            .find_subcommand_mut("connect")
            .unwrap()
            .render_long_help()
            .to_string();
        assert!(help.contains("--quality <PRESET>"), "{help}");
        assert!(help.contains("best-performance"), "{help}");
    }

    /// The quality design §3.6: `tornect demo` with its defaults (1920×1080
    /// at 30 fps, Balanced, 10 s, one encoder thread) and each option in its
    /// range; the two mode flags are parsed so that their absence is said
    /// with exit code 2 (`demo_cmd::ONLY_LOOPBACK`), not by the parser.
    #[test]
    fn demo_takes_its_options_within_their_ranges() {
        use tornect_core::config::QualityPreset;
        let parse =
            |args: &[&str]| super::Cli::try_parse_from(["tornect", "demo"].iter().chain(args));
        let demo_of = |args: &[&str]| match parse(args).unwrap().command {
            Some(super::Command::Demo {
                loopback,
                headless_stats,
                size,
                fps,
                quality,
                seconds,
                threads,
            }) => (
                loopback,
                headless_stats,
                size,
                fps,
                quality,
                seconds,
                threads,
            ),
            other => panic!("not demo: {other:?}"),
        };
        assert_eq!(
            demo_of(&["--loopback", "--headless-stats"]),
            (true, true, (1920, 1080), 30, QualityPreset::Balanced, 10, 1)
        );
        assert_eq!(
            demo_of(&[
                "--loopback",
                "--headless-stats",
                "--size",
                "3538x1918",
                "--fps",
                "60",
                "--quality",
                "best-performance",
                "--seconds",
                "3",
                "--threads",
                "0",
            ]),
            (
                true,
                true,
                (3538, 1918),
                60,
                QualityPreset::BestPerformance,
                3,
                0
            )
        );
        assert_eq!(
            demo_of(&[]),
            (
                false,
                false,
                (1920, 1080),
                30,
                QualityPreset::Balanced,
                10,
                1
            ),
            "parsed, then refused by the demo itself"
        );
        for wrong in [
            &["--size", "100x100"][..],
            &["--size", "1920"],
            &["--fps", "0"],
            &["--fps", "241"],
            &["--quality", "fast"],
            &["--seconds", "0"],
            &["--seconds", "3601"],
            &["--threads", "5"],
            &["--threads", "-1"],
        ] {
            assert!(parse(wrong).is_err(), "{wrong:?}");
        }
        assert_eq!(
            super::demo_cmd::ONLY_LOOPBACK,
            "demo: only --loopback --headless-stats is available"
        );
    }

    /// `tornect connect --unattended`: its options need it, it never pairs,
    /// and a `--password` is parsed only to be refused with the reason.
    #[test]
    fn the_unattended_connect_takes_no_password_on_the_command_line() {
        let parse = |args: &[&str]| {
            super::Cli::try_parse_from(["tornect", "connect", ID].iter().chain(args))
        };
        assert!(parse(&["--unattended", "--view-only", "--remember"]).is_ok());
        assert!(
            parse(&["--view-only"]).is_err(),
            "--view-only needs --unattended"
        );
        assert!(parse(&["--remember"]).is_err());
        assert!(parse(&["--administrator"]).is_err());
        assert!(parse(&["--unattended", "--pair-only"]).is_err());
        assert!(parse(&["--unattended", "--forget"]).is_err());
        assert!(
            parse(&["--unattended", "--view-only", "--administrator"]).is_err(),
            "the level goes with control only"
        );
        for args in [
            &["--unattended", "--password", "hunter2"][..],
            &["--unattended", "--password=hunter2"],
            &["--unattended", "--password"],
        ] {
            let cli = parse(args).expect("parsed, to be refused");
            let Some(super::Command::Connect { password, .. }) = cli.command else {
                panic!("not connect");
            };
            let err =
                super::ua_client::refuse_password_sources(password.is_some(), std::iter::empty())
                    .unwrap_err()
                    .to_string();
            assert!(
                err.contains("never takes a password on the command line"),
                "{err}"
            );
            assert!(!err.contains("hunter2"));
        }
        let help = super::Cli::command()
            .find_subcommand_mut("connect")
            .unwrap()
            .render_long_help()
            .to_string();
        assert!(!help.contains("--password"), "the refused option is hidden");
        assert!(help.contains("--unattended"));
        let admin =
            |args: &[&str]| super::Cli::try_parse_from(["tornect", "admin", ID].iter().chain(args));
        assert!(admin(&["revoke-this-device"]).is_ok());
        assert!(admin(&["unlock"]).is_err(), "unlock names the device");
        assert!(admin(&["end-session", "--password", "x"]).is_ok());
    }

    /// The installed copy's entry step is the whole command line: the
    /// program and `install-entry`, nothing before or after it, in that case
    /// only; anything else is not the step, and the parser refuses it.
    #[test]
    fn the_entry_step_takes_no_other_argument() {
        let args = |a: &[&str]| a.iter().map(std::ffi::OsString::from).collect::<Vec<_>>();
        assert_eq!(
            super::internal_step(&args(&["tornect.exe", "install-entry"])),
            Some(super::InternalStep::InstallEntry)
        );
        for not in [
            &["tornect.exe", "install-entry", "x"][..],
            &["tornect.exe", "--home", "x", "install-entry"],
            &["tornect.exe", "install-entry", "--home", "x"],
            &["tornect.exe", "Install-Entry"],
            &["tornect.exe", "install-entry "],
            &["tornect.exe"],
            &["install-entry"],
            &[],
        ] {
            assert_eq!(super::internal_step(&args(not)), None, "{not:?}");
        }
        assert!(super::Cli::try_parse_from(["tornect", "install-entry"]).is_err());
        assert!(super::Cli::try_parse_from(["tornect", "install-entry", "x"]).is_err());
    }

    /// The installed copy's restart step is the whole command line too: the
    /// program and `remove-at-restart`, nothing before or after it, in that
    /// case only.
    #[test]
    fn the_restart_step_takes_no_other_argument() {
        let args = |a: &[&str]| a.iter().map(std::ffi::OsString::from).collect::<Vec<_>>();
        assert_eq!(
            super::internal_step(&args(&["tornect.exe", "remove-at-restart"])),
            Some(super::InternalStep::RemoveAtRestart)
        );
        for not in [
            &["tornect.exe", "remove-at-restart", "C:\\Windows"][..],
            &["tornect.exe", "--home", "x", "remove-at-restart"],
            &["tornect.exe", "remove-at-restart", "--home", "x"],
            &["tornect.exe", "Remove-At-Restart"],
            &["tornect.exe", "remove-at-restart", "install-entry"],
            &["remove-at-restart"],
        ] {
            assert_eq!(super::internal_step(&args(not)), None, "{not:?}");
        }
        assert!(super::Cli::try_parse_from(["tornect", "remove-at-restart"]).is_err());
    }

    /// B32: `--help` describes what this build does: a remote desktop whose
    /// pictures travel over Tor, not the direct QUIC or the game streaming
    /// that later milestones plan; and `connect` no longer says there is no
    /// viewer window, which the window has.
    #[test]
    fn the_help_describes_this_build() {
        let help = super::Cli::command().render_help().to_string();
        assert!(
            help.contains(
                "Tornect — remote desktop over Tor onion services: no servers, no accounts, no \
                 port forwarding"
            ),
            "{help}"
        );
        for stale in ["QUIC", "game streaming", "Milestone"] {
            assert!(!help.contains(stale), "`{stale}` in:\n{help}");
        }
        let connect = super::Cli::command()
            .find_subcommand_mut("connect")
            .unwrap()
            .render_long_help()
            .to_string();
        let connect = connect.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(!connect.contains("no viewer window"), "{connect}");
        assert!(
            connect.contains("the window, `tornect` without a subcommand, shows them"),
            "{connect}"
        );
    }

    /// U3-L3: `--help` says that no log filter writes identifiers, and
    /// which option does; FX1-I2: it says what the redaction does not cover
    /// (message and error texts, and with --json-logs the warnings).
    #[test]
    fn the_help_says_the_log_names_nobody_without_the_opt_in() {
        let help = super::Cli::command().render_long_help().to_string();
        let help = help.split_whitespace().collect::<Vec<_>>().join(" ");
        for said in [
            "Under every filter the fields of a log line that name a device, a person or a \
             computer read `<redacted>`; `--log-identifiers` writes them",
            "Message and error texts are written as they are: they can quote a path, or a line \
             of a file that holds a Tornect ID",
            "With --json-logs, warnings and errors are written in full",
            "Below WARN, a line with a field that names a device, a person or a computer is \
             left out unless --log-identifiers is given; warnings and errors are written in full",
            "--log-identifiers",
            "TORNECT_LOG_IDENTIFIERS=1",
        ] {
            assert!(help.contains(said), "\"{said}\" missing:\n{help}");
        }
    }

    /// The running Tornect of a test: it holds the host lock and serves the
    /// control channel with `answer`; dropped, it stops serving.
    struct FirstInstance {
        _lock: super::host::HostLock,
        serving: tokio::task::JoinHandle<()>,
    }

    impl Drop for FirstInstance {
        fn drop(&mut self) {
            self.serving.abort();
        }
    }

    async fn first_instance<F, Fut>(paths: &tornect_core::Paths, answer: F) -> FirstInstance
    where
        F: Fn(IpcRequest) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = IpcResponse> + Send + 'static,
    {
        paths.ensure().unwrap();
        let lock = super::host::HostLock::acquire(paths).unwrap();
        let endpoint = tornect_platform::ipc::Endpoint::bind(&paths.state_dir)
            .await
            .unwrap();
        let serving = tokio::spawn(async move {
            let _ = endpoint.serve(answer).await;
        });
        FirstInstance {
            _lock: lock,
            serving,
        }
    }

    /// The first instance as a host serves it: the real dispatch over a
    /// store in `home`, with `show` as its window's raise (`None`: no window).
    async fn host_in(
        home: &std::path::Path,
        show: Option<super::unattended::ShowHook>,
    ) -> FirstInstance {
        let ctx = Arc::new(super::unattended::test_context(home, show));
        first_instance(&tornect_core::Paths::from_home(home), move |req| {
            let ctx = Arc::clone(&ctx);
            async move { super::unattended::dispatch(&ctx, req) }
        })
        .await
    }

    /// §B.1.1 (row 9's test): a second launch finds the running window host,
    /// which raises its window, and ends there: no second window.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_second_launch_shows_the_first() {
        let tmp = tempfile::tempdir().unwrap();
        let raised = Arc::new(AtomicUsize::new(0));
        let hook: super::unattended::ShowHook = {
            let raised = Arc::clone(&raised);
            Arc::new(move |link| {
                assert_eq!(link, None, "a second launch sends no link");
                raised.fetch_add(1, Ordering::SeqCst);
            })
        };
        let first = host_in(tmp.path(), Some(hook)).await;
        let paths = tornect_core::Paths::from_home(tmp.path());
        assert!(super::shown_by_the_running_host(&paths, None).await);
        assert_eq!(raised.load(Ordering::SeqCst), 1, "raised once");
        drop(first);
    }

    /// A first instance with no window to raise (the terminal or the
    /// headless host) refuses `Show`, a link's too (design `invite` §2.4: the
    /// link then opens a connect-only window), and with nothing running
    /// nothing is asked: the second launch opens its window as before.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refused_show_keeps_todays_second_window() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = tornect_core::Paths::from_home(tmp.path());
        paths.ensure().unwrap();
        for link in [
            None,
            Some(ShownLink::Fill(key(7))),
            Some(ShownLink::Refused),
        ] {
            assert!(
                !super::shown_by_the_running_host(&paths, link).await,
                "nothing runs"
            );
        }
        let first = host_in(tmp.path(), None).await;
        for link in [
            None,
            Some(ShownLink::Fill(key(7))),
            Some(ShownLink::Refused),
        ] {
            assert!(
                !super::shown_by_the_running_host(&paths, link).await,
                "refused: {link:?}"
            );
        }
        drop(first);
    }

    /// A real key's ID, from its seed byte.
    fn key(seed: u8) -> tornect_core::TornectId {
        tornect_core::TornectId::from_public_key(
            &ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key(),
        )
    }

    /// The first instance as a window host whose raise records what each
    /// `Show` carried.
    async fn recording_host(
        home: &std::path::Path,
    ) -> (FirstInstance, Arc<std::sync::Mutex<Vec<Option<ShownLink>>>>) {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let hook: super::unattended::ShowHook = {
            let seen = Arc::clone(&seen);
            Arc::new(move |link| seen.lock().unwrap().push(link))
        };
        (host_in(home, Some(hook)).await, seen)
    }

    /// Design `invite` §2.4: a link opened while the window host runs raises
    /// that window with the link's ID, read strictly from the link the OS
    /// passed, and the launch ends there (no second window). Nothing is
    /// written to `sessions.log`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_link_launch_fills_the_running_window() {
        let tmp = tempfile::tempdir().unwrap();
        let (first, seen) = recording_host(tmp.path()).await;
        let paths = tornect_core::Paths::from_home(tmp.path());
        let log = tornect_core::session_log::SessionLog::new(paths.sessions_log());
        let lines = log.read_all().unwrap().len();
        let id = key(9);
        let shown = super::shown_link(std::ffi::OsStr::new(&tornect_core::invite::link(&id)));
        assert_eq!(shown, ShownLink::Fill(id));
        assert!(super::shown_by_the_running_host(&paths, Some(shown)).await);
        assert_eq!(*seen.lock().unwrap(), vec![Some(ShownLink::Fill(id))]);
        assert_eq!(log.read_all().unwrap().len(), lines, "nothing logged");
        drop(first);
    }

    /// Design `invite` §2.4: a link that holds no valid ID still raises the
    /// running window, which is told it was refused (so it can say why
    /// nothing was filled in), and the launch ends there.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_refused_link_still_raises_the_running_window() {
        let tmp = tempfile::tempdir().unwrap();
        let (first, seen) = recording_host(tmp.path()).await;
        let paths = tornect_core::Paths::from_home(tmp.path());
        let with_extras = format!("{}?connect=1", tornect_core::invite::link(&key(9)));
        let shown = super::shown_link(std::ffi::OsStr::new(&with_extras));
        assert_eq!(shown, ShownLink::Refused);
        assert!(super::shown_by_the_running_host(&paths, Some(shown)).await);
        assert_eq!(*seen.lock().unwrap(), vec![Some(ShownLink::Refused)]);
        drop(first);
    }

    /// Design `invite` §2.4, L-5: the window a link opens with no Tornect
    /// window running is connect-only, for a fill and a refusal alike: it
    /// takes no host lock, publishes nothing and serves no IPC, so no
    /// unattended grant can be served from it.
    #[test]
    fn the_link_window_is_connect_only() {
        for shown in [ShownLink::Fill(key(9)), ShownLink::Refused] {
            for bridges in [None, Some(BridgeMode::Snowflake)] {
                let opts = super::link_window_opts(bridges, shown);
                assert!(!opts.host, "{shown:?}");
                assert!(!opts.preview);
                assert_eq!(opts.link, Some(shown));
                assert_eq!(opts.bridges, bridges);
            }
        }
    }

    /// L-5 (review): what a link launch does is decided apart from the
    /// window, so its wiring is tested: the running window is asked first,
    /// with exactly what was read of the link; when it took the link,
    /// nothing opens; otherwise the window that opens is the connect-only
    /// link window, with the link and the launch's bridges, never a preview.
    #[test]
    fn a_link_launch_raises_or_opens_a_connect_only_window() {
        for shown in [ShownLink::Fill(key(9)), ShownLink::Refused] {
            let mut asked = Vec::new();
            let raised = |s| {
                asked.push(s);
                true
            };
            assert!(
                super::link_launch(shown, raised, None).is_none(),
                "{shown:?}"
            );
            assert_eq!(asked, [shown]);

            for bridges in [None, Some(BridgeMode::Obfs4)] {
                let mut asked = Vec::new();
                let refused = |s| {
                    asked.push(s);
                    false
                };
                let opts = super::link_launch(shown, refused, bridges).expect("a window");
                assert_eq!(asked, [shown]);
                assert!(!opts.host, "{shown:?}: a link never starts hosting");
                assert_eq!(opts.link, Some(shown));
                assert_eq!(opts.bridges, bridges);
                assert!(!opts.preview && !opts.empty);
                assert!(opts.page.is_none() && opts.sheet.is_none());
            }
        }
    }

    /// Design `invite` §2.4, §4.1: `open-link` reads its argument with the
    /// strict link grammar alone: an ID that is no link, a link with anything
    /// more, and text that is not UTF-8 are refused, each with its problem.
    #[test]
    fn open_link_reads_only_a_link() {
        use tornect_core::invite::{self, IdProblem};
        let id = key(9);
        let read = |s: &str| super::read_link(std::ffi::OsStr::new(s));
        assert_eq!(read(&invite::link(&id)), Ok(id));
        assert_eq!(read(&format!("tornect:{}.onion/", id.base32())), Ok(id));
        assert_eq!(read(&id.base32()), Err(IdProblem::NotALink));
        assert_eq!(read(&invite::invitation(&id)), Err(IdProblem::LinkExtras));
        assert_eq!(
            read(&format!("{}\" --home C:\\x", invite::link(&id))),
            Err(IdProblem::NotAlphabet(Some('"')))
        );
        assert_eq!(
            read(&format!("{} --home C:\\x", invite::link(&id))),
            Err(IdProblem::LinkExtras)
        );
        assert_eq!(read(""), Err(IdProblem::NotALink));
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt as _;
            let mut bytes = invite::link(&id).into_bytes();
            bytes.push(0xFF);
            assert_eq!(
                super::read_link(std::ffi::OsStr::from_bytes(&bytes)),
                Err(IdProblem::NotALink)
            );
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStringExt as _;
            let mut wide: Vec<u16> = invite::link(&id).encode_utf16().collect();
            wide.push(0xD800);
            assert_eq!(
                super::read_link(&std::ffi::OsString::from_wide(&wide)),
                Err(IdProblem::NotALink)
            );
        }
    }

    /// Design `invite` §2.4, L-3: `open-link` takes exactly one link, after
    /// `--` as the OS passes it, so whatever a link holds (a `"` a browser
    /// left unescaped, `--home`, a subcommand) stays inside that one
    /// argument; a second argument is refused rather than read. The
    /// subcommand is the name the OS registration writes.
    #[test]
    fn open_link_takes_one_link_after_the_separator() {
        let link = tornect_core::invite::link(&key(9));
        let parse = |args: &[&str]| super::Cli::try_parse_from(args.iter().copied());
        let taken = |args: &[&str]| match parse(args).map(|cli| (cli.home, cli.command)) {
            Ok((home, Some(super::Command::OpenLink { link }))) => (home, link),
            other => panic!("{args:?}: {other:?}"),
        };
        assert_eq!(
            taken(&["tornect", "open-link", "--", &link]),
            (None, link.clone().into())
        );
        assert_eq!(
            taken(&["tornect", "open-link", &link]),
            (None, link.clone().into())
        );
        assert_eq!(
            taken(&["tornect", "--home", "/h", "open-link", "--", "L"]),
            (Some(PathBuf::from("/h")), "L".into())
        );
        let injected = "tornect://x\" --home C:\\x";
        assert_eq!(
            taken(&["tornect", "open-link", "--", injected]),
            (None, injected.into())
        );
        assert_eq!(
            taken(&["tornect", "open-link", "--", "--home"]),
            (None, "--home".into())
        );
        for refused in [
            &["tornect", "open-link", "--", "L", "--home", "/x"][..],
            &[
                "tornect",
                "open-link",
                "--",
                "tornect://x\"",
                "--home",
                "C:\\x",
            ],
            &["tornect", "open-link", "L", "extra"],
            &["tornect", "open-link", "--", "L", "gui"],
            &["tornect", "open-link"],
            &["tornect", "open-link", "--"],
            &["tornect", "--background", "open-link", "--", "L"],
        ] {
            let parsed = parse(refused);
            let accepted = parsed
                .as_ref()
                .is_ok_and(|cli| !cli.background || cli.command.is_none());
            assert!(!accepted, "{refused:?}: {parsed:?}");
        }
        assert_eq!(
            tornect_platform::install::LINK_ARGUMENT,
            "open-link",
            "the registration's subcommand"
        );
        assert!(
            super::Cli::command()
                .find_subcommand(tornect_platform::install::LINK_ARGUMENT)
                .is_some()
        );
        let help = super::Cli::command()
            .find_subcommand_mut("open-link")
            .unwrap()
            .render_long_help()
            .to_string();
        let help = help.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            help.contains(
                "Open a tornect:// link: bring Tornect's window forward, or open a connect-only \
                 window, with the link's ID in the connect field. It never connects by itself"
            ),
            "{help}"
        );
    }

    /// Design `invite` §2.5: `tornect id` shows the link under the ID and
    /// its groups, `--json` carries it as `"link"`, and `--invitation`
    /// (which `--json` excludes) is the invitation alone.
    #[test]
    fn id_shows_the_link_and_prints_an_invitation() {
        let id = key(9);
        let device = tornect_core::DeviceId::from_bytes(*key(10).public_key_bytes());
        let link = tornect_core::invite::link(&id);
        let lines = super::id_lines(&id, &device);
        assert_eq!(lines[0], format!("Tornect ID : {}", id.onion_address()));
        assert_eq!(lines[1], format!("           : {}", id.display_groups()));
        assert_eq!(lines[2], format!("Link       : {link}"));
        assert!(lines[3].starts_with("Device ID  : "), "{}", lines[3]);
        let json = super::id_json(&id, &device, false, std::path::Path::new("/k"));
        assert_eq!(json["link"], serde_json::json!(link));
        assert_eq!(json["tornect_id"], serde_json::json!(id.onion_address()));

        let parse = |args: &[&str]| super::Cli::try_parse_from(args.iter().copied());
        assert!(matches!(
            parse(&["tornect", "id", "--invitation"]).unwrap().command,
            Some(super::Command::Id {
                json: false,
                invitation: true
            })
        ));
        assert!(matches!(
            parse(&["tornect", "id"]).unwrap().command,
            Some(super::Command::Id {
                json: false,
                invitation: false
            })
        ));
        let both = parse(&["tornect", "id", "--json", "--invitation"]).unwrap_err();
        assert_eq!(both.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    /// Design `invite` §2.5 (review): what `tornect id` prints in each form.
    /// `--invitation` is exactly the invitation, whether the ID was just
    /// made or not; `--json` is the JSON object; the lines say a new ID
    /// first.
    #[test]
    fn id_prints_each_form_as_designed() {
        use super::IdShown;
        let id = key(9);
        let device = tornect_core::DeviceId::from_bytes(*key(10).public_key_bytes());
        let keystore = std::path::Path::new("/k");
        for created in [false, true] {
            let output = |shown| super::id_output(shown, &id, &device, created, keystore);
            assert_eq!(
                output(IdShown::Invitation),
                tornect_core::invite::invitation(&id),
                "{created}"
            );
            let json: serde_json::Value = serde_json::from_str(&output(IdShown::Json)).unwrap();
            assert_eq!(json, super::id_json(&id, &device, created, keystore));
            let lines = output(IdShown::Lines);
            let shown: Vec<&str> = lines.lines().collect();
            let expected = super::id_lines(&id, &device);
            let expected: Vec<&str> = expected.iter().map(String::as_str).collect();
            assert_eq!(shown[usize::from(created)..], expected);
            assert_eq!(
                created,
                lines.starts_with("Generated a new Tornect ID (stored in /k).\n")
            );
        }
    }

    /// §B.1.1: a `--background` launch (the start at sign-in) parses with no
    /// subcommand, after `--home` too; with a Tornect host running here it
    /// ends at once and sends it nothing, so no `Show` raises a window someone
    /// minimised; with nothing running its window opens.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn background_with_a_running_host_exits_quietly() {
        let cli = super::Cli::try_parse_from(["tornect", "--background"]).unwrap();
        assert!(cli.background && cli.command.is_none());
        let cli =
            super::Cli::try_parse_from(["tornect", "--home", "/srv/t", "--background"]).unwrap();
        assert!(cli.background && cli.command.is_none());
        assert!(!super::Cli::try_parse_from(["tornect"]).unwrap().background);

        let tmp = tempfile::tempdir().unwrap();
        let paths = tornect_core::Paths::from_home(tmp.path());
        paths.ensure().unwrap();
        assert!(!super::background_already_running(&paths), "nothing runs");
        let asked = Arc::new(AtomicUsize::new(0));
        let first = {
            let asked = Arc::clone(&asked);
            first_instance(&paths, move |req| {
                asked.fetch_add(1, Ordering::SeqCst);
                async move { IpcResponse::ok(req.id) }
            })
            .await
        };
        assert!(super::background_already_running(&paths));
        assert_eq!(asked.load(Ordering::SeqCst), 0, "nothing sent: no Show");
        drop(first);
    }

    /// FC-10: a first instance that never answers holds the second launch
    /// for 3 s, not for the 150 s `ipc::request` would wait.
    #[tokio::test(start_paused = true)]
    async fn a_hung_first_instance_does_not_hang_the_second_launch() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = tornect_core::Paths::from_home(tmp.path());
        let first = first_instance(&paths, |_req| async {
            std::future::pending::<IpcResponse>().await
        })
        .await;
        let (t0, real) = (tokio::time::Instant::now(), std::time::Instant::now());
        assert!(!super::shown_by_the_running_host(&paths, None).await);
        let waited = t0.elapsed();
        assert!(
            waited >= super::SHOW_WAIT && waited < super::SHOW_WAIT * 2,
            "{waited:?}"
        );
        assert!(super::SHOW_WAIT < tornect_platform::ipc::RESPONSE_TIMEOUT);
        assert!(real.elapsed() < std::time::Duration::from_secs(30));
        drop(first);
    }
}
