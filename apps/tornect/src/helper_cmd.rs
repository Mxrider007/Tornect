//! `tornect input-helper <pipe> <host pid> <limit s>` (`docs/PLAN.md`
//! §B.8.7.5; r7, M-FEAT-3): the administrator helper, the only part of
//! Tornect that runs elevated. Only the host starts it, through Windows'
//! prompt or the on-demand task, for one session.
//!
//! `main` sends this command here before anything else runs — before the
//! command-line parser (whose `--home` reads `TORNECT_HOME`), the log (which
//! reads `TORNECT_LOG`) and the paths — so the helper reads no config, no
//! environment-derived path and no file (H2); the DLL search was restricted
//! to the system directory first. It opens exactly the pipe it was given,
//! checks the process at the other end (the host's id, the same Program
//! Files image, the same session), says it is ready, and from then on only
//! injects the host's input events until one of its exits, letting go of
//! every key and button first (H3). It watches for the physical panic chord
//! itself. It initialises no Tor, codec or window, and has no launch, file,
//! clipboard, registry, window or network operation.

use std::ffi::OsString;

use tornect_input::helper::Exit;
use tornect_platform::helper::HelperArgs;

/// Run the helper with the arguments after `input-helper`; the process's
/// exit code.
pub fn run(args: &[OsString]) -> i32 {
    let exit = match HelperArgs::parse(args) {
        Ok(args) => serve(&args),
        Err(_) => Exit::BadArguments,
    };
    // One line on a console, when there is one (never a window).
    eprintln!("tornect input-helper: {}", exit.reason());
    exit.code()
}

#[cfg(not(windows))]
fn serve(_: &HelperArgs) -> Exit {
    Exit::Unsupported
}

#[cfg(windows)]
fn serve(args: &HelperArgs) -> Exit {
    use std::sync::{Arc, mpsc};

    use tornect_input::helper::{
        Event, FrameRead, FromHelper, HEARTBEAT_MISSED, Limits, forward_frames, run_helper,
    };
    use tornect_platform::helper as platform;

    /// The helper's end of the pipe, read by the reader thread.
    struct Reader(Arc<platform::HelperPipe>);

    impl FrameRead for Reader {
        fn read_frame(&mut self) -> std::io::Result<Option<[u8; 16]>> {
            self.0.read_frame()
        }
    }

    let Ok(pipe) = platform::connect_pipe(&args.pipe) else {
        return Exit::NoPipe;
    };
    let pipe = Arc::new(pipe);
    let checked = platform::helper_self().and_then(|me| {
        platform::server_facts(&pipe)
            .map(|server| platform::check_server(args.host_pid, &me, &server))
    });
    if !matches!(checked, Ok(Ok(()))) {
        pipe.close();
        return Exit::ServerRefused;
    }
    let (tx, events) = mpsc::channel();
    // The host's exit ends the helper: it waits on the host's process.
    let host_gone = tx.clone();
    if platform::when_exits(args.host_pid, move || {
        let _ = host_gone.send(Event::HostExited);
    })
    .is_err()
    {
        pipe.close();
        return Exit::HostExited;
    }
    // The panic chord, watched here, where an elevated window's keys are
    // seen; without the watch the helper does not run.
    let panicked = tx.clone();
    if platform::watch_panic_chord(move || {
        let _ = panicked.send(Event::PanicChord);
    })
    .is_err()
    {
        pipe.close();
        return Exit::Unsupported;
    }
    if pipe.write_frame(&FromHelper::Ready.encode()).is_err() {
        return Exit::PipeClosed;
    }
    {
        let mut reader = Reader(Arc::clone(&pipe));
        let spawned = std::thread::Builder::new()
            .name("helper-pipe".to_owned())
            .spawn(move || forward_frames(&mut reader, &tx));
        if spawned.is_err() {
            pipe.close();
            return Exit::PipeClosed;
        }
    }
    // The same mapping as the host's own injector: the viewer's pointer over
    // the part of the desktop it sees.
    let sink = tornect_input::windows::SendInputSink::new().over(tornect_codec::encoded_size);
    let exit = run_helper(
        sink,
        &events,
        Limits {
            heartbeat: HEARTBEAT_MISSED,
            hard_cap: args.hard_cap,
        },
        &mut || {
            let _ = pipe.write_frame(&FromHelper::Panic.encode());
        },
    );
    pipe.close();
    exit
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Anything but `<pipe> <host pid> <limit s>` ends the helper at once
    /// with its own code; on this system (not Windows) a well-formed command
    /// line ends it as unsupported, before any pipe is opened.
    #[test]
    fn the_helper_ends_at_once_without_its_pipe() {
        assert_eq!(run(&[]), Exit::BadArguments.code());
        assert_eq!(
            run(&[OsString::from("--home"), OsString::from("x")]),
            Exit::BadArguments.code()
        );
        let args = HelperArgs {
            pipe: tornect_platform::helper::pipe_name(&[3; 16]),
            host_pid: 1,
            hard_cap: std::time::Duration::from_secs(60),
        }
        .to_args()
        .into_iter()
        .map(OsString::from)
        .collect::<Vec<_>>();
        let code = run(&args);
        if cfg!(windows) {
            assert_eq!(code, Exit::NoPipe.code(), "no such pipe");
        } else {
            assert_eq!(code, Exit::Unsupported.code());
        }
    }
}
