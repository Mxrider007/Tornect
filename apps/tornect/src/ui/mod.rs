//! The desktop window (`tornect` with no subcommand, or `tornect gui`): the
//! D10 egui-everywhere fallback of `docs/research/slice.md` §2 for the
//! vertical slice. A manual winit loop drives egui-winit and egui-wgpu (never
//! eframe) on the main thread; Tor, hosting and viewing run on a tokio runtime
//! beside it (`backend`).
//!
//! What it shows (`docs/UI_PLAN.md` §5–§8, reconciled in `docs/PLAN.md` Part
//! G): the home screen with this machine's ID, the Tor status and the transport
//! in use, a connect field; the host's pairing and session popups and the
//! client's code comparison (`consent`, replacing the terminal's `prompt`);
//! the persistent sharing banner with Stop, and the same in a small
//! always-on-top window of its own for as long as the screen is shared
//! (`indicator`); before an unattended session starts, its block window with
//! Block on every monitor, and its "Ask before starting" sheet (`block`,
//! `consent`); the stream window, which draws the
//! host's screen and sends input by physical scancode in a control session
//! (`stream`, `keys`); and on a Wayland desktop the first-run screen-sharing
//! grant (the operator's decision of 2026-09-23).

mod app;
mod backend;
mod block;
pub(crate) mod book;
mod consent;
mod icons;
mod indicator;
mod keys;
pub(crate) mod model;
mod nav;
mod notice;
mod pages;
pub(crate) mod preview;
pub(crate) mod recognize;
mod screenshot;
mod stream;
mod theme;
mod view;
mod widgets;

use std::sync::{Arc, Mutex, PoisonError};

use anyhow::Context as _;
use tokio::sync::mpsc;
use tornect_core::config::BridgeMode;
use tornect_core::keystore::{
    FileSecretStore, load_or_create_device_identity, load_or_create_host_identity,
};
use tornect_core::unattended::ipc::ShownLink;
use tornect_core::{Config, DeviceIdentity, HostIdentity, Paths};
use tornect_session::{DesktopBackend, Source};
use tornect_signal::{HostSigner, install_crypto_provider, shutdown_runtime};
use winit::event_loop::EventLoop;

use self::app::{App, UserEvent};
use self::backend::{Backend, StreamLink};
use self::consent::Popups;
use self::model::{Hosting, Model, Setup, Shared, Wake, Waker};
pub use self::nav::Page;

/// The next request to end this process: SIGINT or SIGTERM on Unix (Ctrl-C
/// in the terminal that started it, `kill`, `systemctl stop`), Ctrl-C or
/// Ctrl-Break on Windows. Once listened for, these no longer end the process
/// by themselves; the window's close path does.
async fn quit_requested() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut interrupt = signal(SignalKind::interrupt())?;
        let mut terminate = signal(SignalKind::terminate())?;
        tokio::select! {
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        let mut ctrl_break = tokio::signal::windows::ctrl_break()?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = ctrl_break.recv() => Ok(()),
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        std::future::pending().await
    }
}

/// How the window runs.
#[derive(Debug, Clone, Copy)]
pub struct GuiOpts {
    /// What a shared session shows.
    pub source: Source,
    /// Publish this ID and answer requests (`false`: only connect to others).
    pub host: bool,
    /// The command line's bridge mode, over the configuration's.
    pub bridges: Option<BridgeMode>,
    /// Show every screen from synthetic state, with a moving test card in the
    /// stream window, and start nothing: no Tor, no hosting, no network
    /// (`docs/UI_PLAN.md` §10's preview harness, in miniature).
    pub preview: bool,
    /// With `preview`: open on this page, at rest (no question, no session,
    /// no stream window), instead of showing every screen at once.
    pub page: Option<Page>,
    /// With `preview`: an empty address book (a first run).
    pub empty: bool,
    /// With `preview` and `page`: one host sheet of this kind on screen.
    pub sheet: Option<preview::Sheet>,
    /// With `preview`: the theme the windows draw with (a real window draws
    /// with the one saved in the settings).
    pub theme: egui::Theme,
    /// The `tornect:` link this window was opened for (`tornect open-link`,
    /// design `invite` §2.4): at most an ID for the connect field. A window
    /// opened for a link does not host.
    pub link: Option<ShownLink>,
}

/// Why a window opened for a link answers no request (design `invite` §2.4):
/// the ID card's line reads "Incoming requests: off (…)" with this.
pub(crate) const LINK_WINDOW_OFF: &str =
    "opened from a link; open Tornect itself to answer requests";

/// The hosting line a window starts with: waiting for Tor when it hosts,
/// else off, saying why.
fn first_hosting(host: bool, link: Option<ShownLink>) -> Hosting {
    match (host, link) {
        (true, _) => Hosting::Waiting,
        (false, Some(_)) => Hosting::Off(LINK_WINDOW_OFF.to_owned()),
        (false, None) => Hosting::Off("started with --no-host".to_owned()),
    }
}

/// What the window starts from: its first model and, for a real window (not
/// the preview), what the tokio side needs.
struct Start {
    model: Model,
    real: Option<Real>,
}

/// A real window's configuration and identities.
struct Real {
    cfg: Config,
    identity: HostIdentity,
    device: DeviceIdentity,
    device_pk: [u8; 32],
}

/// Read (on first run: create) what the window needs. The preview branches
/// first (review F-1): it creates no directory, opens no keystore, loads or
/// creates no identity and reads no configuration, and it shows a made-up ID,
/// so that nothing of this machine can reach its pictures.
fn start(paths: &Paths, opts: &GuiOpts) -> anyhow::Result<Start> {
    if opts.preview {
        let mut model = preview::model(opts.page.is_none(), opts.empty);
        if let Some(sheet) = opts.sheet {
            preview::sheet(&mut model, sheet);
        }
        model.settings.theme = match opts.theme {
            egui::Theme::Dark => tornect_core::config::Theme::Dark,
            egui::Theme::Light => tornect_core::config::Theme::Light,
        };
        return Ok(Start { model, real: None });
    }
    paths.ensure().context("creating Tornect directories")?;
    let store = FileSecretStore::open(paths.keys_dir()).context("opening keystore")?;
    let (identity, _) = load_or_create_host_identity(&store)?;
    let (device, _) = load_or_create_device_identity(&store)?;
    let device_pk = HostSigner::public_key(&device);
    let mut cfg = Config::load(&paths.config_file())?;
    // What the file holds, before the command line's overrides.
    let settings = model::Settings::of(&cfg);
    if let Some(mode) = opts.bridges {
        cfg.tor.bridges = mode;
    }
    // The first-run grant is a step only where a session would open the
    // desktop's portal: a Wayland desktop this machine shares.
    let setup = (opts.host
        && opts.source == Source::Desktop
        && DesktopBackend::detect() == DesktopBackend::Wayland)
        .then(|| {
            let token_file = paths.portal_restore_token();
            Setup {
                granted: token_file.exists(),
                token_file,
                busy: false,
                note: None,
            }
        });
    let model = Model {
        id: Some(identity.id().display_groups()),
        device_name: cfg.general.device_name.clone(),
        settings,
        book: book::read(paths, tornect_core::address_book::Day::today(), None),
        hosting: first_hosting(opts.host, opts.link),
        setup,
        ..Model::default()
    };
    Ok(Start {
        model,
        real: Some(Real {
            cfg,
            identity,
            device,
            device_pk,
        }),
    })
}

/// Open the window and run until it is closed; with `background`, minimised,
/// as the start at sign-in does (`tornect --background`, §B.1.1): unattended
/// sessions wait until the indicator has been shown.
pub fn run(paths: &Paths, opts: GuiOpts, background: bool) -> anyhow::Result<()> {
    install_crypto_provider();
    let Start { model, real } = start(paths, &opts)?;

    let event_loop = EventLoop::<UserEvent>::with_user_event()
        .build()
        .context("no desktop to open a window on (for the command line, see `tornect --help`)")?;
    let proxy = Mutex::new(event_loop.create_proxy());
    let wake: Waker = Arc::new(move |why| {
        // Fails only once the loop has exited, when nobody needs waking.
        let _ = proxy
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .send_event(UserEvent::Wake(why));
    });
    let quit_wake = Arc::clone(&wake);
    let shared = Shared::new(model, wake);
    let popups = Popups::new(Arc::clone(&shared));
    let link = Arc::new(StreamLink::default());
    let (commands, commands_rx) = mpsc::unbounded_channel();

    let Some(real) = real else {
        // The preview: nothing runs behind the window, and answers go nowhere.
        // Its model came ready-made: one wake opens what it shows (the full
        // preview's stream window), as the first update of a real window does.
        shared.wake(Wake::Model);
        if opts.page.is_none() {
            let (slot, frames) = (Arc::clone(&link.slot), Arc::clone(&shared));
            std::thread::Builder::new()
                .name("tornect-preview".to_owned())
                .spawn(move || preview::card(slot, frames))
                .context("starting the preview's test card")?;
        }
        drop(commands_rx);
        let first = shared.read(|m| m.book.computers.first().map(|c| c.id));
        let mut app = App::new(shared, popups, link, commands);
        if let Some(page) = opts.page {
            app.open_page(page);
        }
        if let Some(sheet) = opts.sheet {
            preview::form(app.form_mut(), sheet, first);
            if let Some(height) = preview::height(sheet) {
                app.height = height;
            }
        }
        app.stream_at = Some((1210, 0));
        let ran = event_loop.run_app(&mut app);
        ran.context("the window's event loop failed")?;
        return app.error.take().map_or(Ok(()), Err);
    };

    // Background mode (§B.1.1): the "indicator shown" fact that the window's
    // probe sets and the host's gate reads.
    let (gate_fact, probe_fact) = indicator_fact(background, opts.host);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("creating the tokio runtime")?;
    // A signal ends the window's sessions as its close button does, instead
    // of killing the process with a session live (which left the viewer's
    // held keys down and `sessions.log` without an end record).
    runtime.spawn(async move {
        loop {
            match quit_requested().await {
                Ok(()) => quit_wake(Wake::Quit),
                Err(e) => {
                    tracing::warn!(error = %e, "cannot listen for quit signals");
                    return;
                }
            }
        }
    });
    // The device words of this home: this computer's, the saved keys', the
    // alarm's (§B.6.1).
    let words = Arc::new(recognize::Recognizer::new(
        paths.clone(),
        recognize::Me {
            name: real.cfg.general.device_name.clone(),
            onion: real.identity.id(),
            device: tornect_core::DeviceId::from_bytes(real.device_pk),
        },
    ));
    runtime.spawn(backend::run(
        Backend {
            paths: paths.clone(),
            cfg: real.cfg,
            shared: Arc::clone(&shared),
            popups: Arc::clone(&popups),
            link: Arc::clone(&link),
            source: opts.source,
            host: opts.host,
            words,
            identity: Arc::new(real.identity),
            device: Arc::new(real.device),
            device_pk: real.device_pk,
            background: gate_fact,
            hosted_store: std::sync::OnceLock::new(),
        },
        commands_rx,
    ));

    let mut app = App::new(shared, popups, link, commands);
    app.screenshots = true;
    app.background = probe_fact;
    if !opts.host {
        app.title = "Tornect (connect only)";
    }
    let ran = event_loop.run_app(&mut app);
    // Arti's final state flush happens as its runtime shuts down.
    shutdown_runtime(runtime);
    ran.context("the window's event loop failed")?;
    match app.error.take() {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// The "indicator shown" fact of background mode (§B.1.1) for the two halves
/// of the window: the host's gate (`Backend`) and the window's probe (`App`).
/// One fact, shared, when the window hosts in background mode, so that what
/// the probe sets is what the gate reads (a gate given none would serve
/// unattended sessions before any indicator was shown); none otherwise.
fn indicator_fact(
    background: bool,
    host: bool,
) -> (
    Option<crate::host::IndicatorShown>,
    Option<crate::host::IndicatorShown>,
) {
    let fact = (background && host).then(crate::host::IndicatorShown::default);
    (fact.clone(), fact)
}

#[cfg(test)]
mod tests {
    use tornect_core::unattended::ipc::ShownLink;

    use super::model::Hosting;

    /// Design `invite` §2.4, L-5: a window opened for a link, a fill or a
    /// refusal, starts connect-only with the line that says why it answers
    /// nothing; `--no-host` keeps its own line; a hosting window waits for
    /// Tor as before. The real set-up, from a fresh home, gives the same.
    #[test]
    fn a_link_window_says_why_it_answers_no_request() {
        let id = tornect_core::TornectId::from_public_key(
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key(),
        );
        for link in [ShownLink::Fill(id), ShownLink::Refused] {
            assert_eq!(
                super::first_hosting(false, Some(link)),
                Hosting::Off(super::LINK_WINDOW_OFF.to_owned())
            );
            assert_eq!(super::first_hosting(true, Some(link)), Hosting::Waiting);
        }
        assert_eq!(
            super::first_hosting(false, None),
            Hosting::Off("started with --no-host".to_owned())
        );
        assert_eq!(super::first_hosting(true, None), Hosting::Waiting);
        assert_eq!(
            super::LINK_WINDOW_OFF,
            "opened from a link; open Tornect itself to answer requests"
        );

        let tmp = tempfile::tempdir().unwrap();
        let paths = tornect_core::Paths::from_home(tmp.path());
        let opts = super::GuiOpts {
            source: tornect_session::Source::Desktop,
            host: false,
            bridges: None,
            preview: false,
            page: None,
            empty: false,
            sheet: None,
            theme: egui::Theme::Dark,
            link: Some(ShownLink::Refused),
        };
        let start = super::start(&paths, &opts).unwrap();
        assert!(start.real.is_some());
        assert_eq!(
            start.model.hosting,
            Hosting::Off(super::LINK_WINDOW_OFF.to_owned())
        );
        assert!(start.model.setup.is_none(), "no first-run screen grant");
    }

    /// §B.1.1 (MUST): in background mode the host's gate and the window's
    /// probe hold one "indicator shown" fact: the one the probe sets is the
    /// one the gate reads. Without background mode, or in a window that
    /// does not host, neither has one.
    #[test]
    fn background_mode_gives_the_gate_and_the_probe_one_fact() {
        let (gate, probe) = super::indicator_fact(true, true);
        let gate = gate.expect("the gate has the fact");
        let probe = probe.expect("the probe has the fact");
        assert!(!gate.is_set() && !probe.is_set());
        probe.set();
        assert!(
            gate.is_set(),
            "the gate reads another fact than the probe sets"
        );
        for (background, host) in [(true, false), (false, true), (false, false)] {
            let (gate, probe) = super::indicator_fact(background, host);
            assert!(
                gate.is_none() && probe.is_none(),
                "background {background}, host {host}"
            );
        }
    }

    /// A SIGTERM (what `kill` and a desktop's logout send) no longer ends the
    /// window's process abruptly: it is a quit request, which the window turns
    /// into its close path (every session ended with a goodbye). The process
    /// survives the signal, so this test can send it to itself.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_terminate_signal_is_a_quit_request() {
        let waiting = tokio::spawn(super::quit_requested());
        // Let the listener register before the signal is sent.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        // kill(2), not a `kill` process: a fork would hold a copy of the
        // other tests' store locks until it execs.
        rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::TERM)
            .unwrap();
        let asked = tokio::time::timeout(std::time::Duration::from_secs(5), waiting)
            .await
            .expect("SIGTERM was not seen as a quit request")
            .unwrap();
        assert!(asked.is_ok(), "{asked:?}");
    }
}
