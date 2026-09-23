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
//! the persistent sharing banner with Stop; the stream window, which draws the
//! host's screen and sends input by physical scancode in a control session
//! (`stream`, `keys`); and on a Wayland desktop the first-run screen-sharing
//! grant (the operator's decision of 2026-09-23).

mod app;
mod backend;
mod consent;
mod keys;
mod model;
mod preview;
mod stream;
mod view;

use std::sync::{Arc, Mutex, PoisonError};

use anyhow::Context as _;
use tokio::sync::mpsc;
use tornect_core::config::BridgeMode;
use tornect_core::keystore::{
    FileSecretStore, load_or_create_device_identity, load_or_create_host_identity,
};
use tornect_core::{Config, Paths};
use tornect_session::{DesktopBackend, Source};
use tornect_signal::{HostSigner, install_crypto_provider, shutdown_runtime};
use winit::event_loop::EventLoop;

use self::app::{App, UserEvent};
use self::backend::{Backend, StreamLink};
use self::consent::Popups;
use self::model::{Hosting, Model, Setup, Shared, Waker};

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
}

/// Open the window and run until it is closed.
pub fn run(paths: &Paths, opts: GuiOpts) -> anyhow::Result<()> {
    install_crypto_provider();
    paths.ensure().context("creating Tornect directories")?;
    let store = FileSecretStore::open(paths.keys_dir()).context("opening keystore")?;
    let (identity, _) = load_or_create_host_identity(&store)?;
    let (device, _) = load_or_create_device_identity(&store)?;
    let device_pk = HostSigner::public_key(&device);
    let mut cfg = Config::load(&paths.config_file())?;
    if let Some(mode) = opts.bridges {
        cfg.tor.bridges = mode;
    }

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
        hosting: if opts.host {
            Hosting::Waiting
        } else {
            Hosting::Off("started with --no-host".to_owned())
        },
        setup,
        ..Model::default()
    };
    let shared = Shared::new(model, wake);
    let popups = Popups::new(Arc::clone(&shared));
    let link = Arc::new(StreamLink::default());
    let (commands, commands_rx) = mpsc::unbounded_channel();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("creating the tokio runtime")?;
    if opts.preview {
        preview::fill(&shared, &paths.portal_restore_token());
        let (slot, frames) = (Arc::clone(&link.slot), Arc::clone(&shared));
        std::thread::Builder::new()
            .name("tornect-preview".to_owned())
            .spawn(move || preview::card(slot, frames))
            .context("starting the preview's test card")?;
        drop(commands_rx);
        let mut app = App::new(shared, popups, link, commands);
        app.stream_at = Some((600, 0));
        let ran = event_loop.run_app(&mut app);
        runtime.shutdown_background();
        ran.context("the window's event loop failed")?;
        return app.error.take().map_or(Ok(()), Err);
    }
    runtime.spawn(backend::run(
        Backend {
            paths: paths.clone(),
            cfg,
            shared: Arc::clone(&shared),
            popups: Arc::clone(&popups),
            link: Arc::clone(&link),
            source: opts.source,
            host: opts.host,
            identity: Arc::new(identity),
            device: Arc::new(device),
            device_pk,
        },
        commands_rx,
    ));

    let mut app = App::new(shared, popups, link, commands);
    let ran = event_loop.run_app(&mut app);
    // Arti's final state flush happens as its runtime shuts down.
    shutdown_runtime(runtime);
    ran.context("the window's event loop failed")?;
    match app.error.take() {
        Some(e) => Err(e),
        None => Ok(()),
    }
}
