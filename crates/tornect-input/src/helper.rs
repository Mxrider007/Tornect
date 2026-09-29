//! The administrator helper's channel (`docs/PLAN.md` §B.8.7.5; r7,
//! M-FEAT-3): the frames the host and `tornect input-helper` exchange over the
//! per-session pipe, the helper's loop with its exits, and the host's end of
//! an attached helper.
//!
//! Every frame is [`FRAME_LEN`] bytes. Host to helper: the input events of
//! [`InputEvent::encode`] (`ReleaseAll` included), [`ToHelper::Heartbeat`] and
//! [`ToHelper::Stop`]. Helper to host: [`FromHelper::Ready`] once, after the
//! helper's own checks, and [`FromHelper::Panic`] when the person at the
//! computer pressed the panic chord. Any other 16 bytes, and a frame cut
//! short, end the helper (H1): an input frame counts only in the one encoding
//! [`InputEvent::encode`] writes for it.
//!
//! Everything here is platform-neutral and runs over any byte pipe (tests:
//! a Unix socket pair); the Windows named pipe, the process checks and the
//! panic-chord hook live in `tornect-platform`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::{InputError, InputEvent, InputSink, Tracked};

/// The length of every frame, both ways.
pub const FRAME_LEN: usize = 16;

/// How often the host sends [`ToHelper::Heartbeat`].
pub const HEARTBEAT_EVERY: Duration = Duration::from_secs(1);
/// The helper ends when no frame came for this long (§B.8.7.5: a missed
/// heartbeat, at most 2 s).
pub const HEARTBEAT_MISSED: Duration = Duration::from_secs(2);
/// The helper's hard cap when the session has no shorter maximum
/// (§B.8.7.5: the session maximum, or 12 h).
pub const HARD_CAP: Duration = Duration::from_secs(12 * 3600);

const KIND_HEARTBEAT: u8 = 0xF0;
const KIND_STOP: u8 = 0xF1;
const KIND_READY: u8 = 0xE0;
const KIND_PANIC: u8 = 0xE1;

fn control(kind: u8) -> [u8; FRAME_LEN] {
    let mut frame = [0u8; FRAME_LEN];
    frame[0] = kind;
    frame
}

fn is_control(frame: &[u8; FRAME_LEN], kind: u8) -> bool {
    frame[0] == kind && frame[1..].iter().all(|b| *b == 0)
}

/// A frame the host sends the helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToHelper {
    /// Inject this event ([`InputEvent::ReleaseAll`] lets go of everything).
    Input(InputEvent),
    /// The host is alive.
    Heartbeat,
    /// The session is over: let go of everything and exit.
    Stop,
}

impl ToHelper {
    /// The 16 bytes on the pipe.
    #[must_use]
    pub fn encode(&self) -> [u8; FRAME_LEN] {
        match self {
            Self::Input(event) => event.encode(),
            Self::Heartbeat => control(KIND_HEARTBEAT),
            Self::Stop => control(KIND_STOP),
        }
    }

    /// The frame `bytes` is, only in its one valid encoding: anything else
    /// is refused (H1).
    pub fn decode(bytes: &[u8; FRAME_LEN]) -> Result<Self, InputError> {
        if is_control(bytes, KIND_HEARTBEAT) {
            return Ok(Self::Heartbeat);
        }
        if is_control(bytes, KIND_STOP) {
            return Ok(Self::Stop);
        }
        let event = InputEvent::decode(bytes)?;
        // `decode` bounds every field it reads but ignores the ones a kind
        // does not use: only the canonical encoding passes here.
        if event.encode() != *bytes {
            return Err(InputError::Malformed("not the canonical encoding"));
        }
        Ok(Self::Input(event))
    }
}

/// A frame the helper sends the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FromHelper {
    /// Connected, and the host passed the helper's checks.
    Ready,
    /// The person at the computer pressed the panic chord: the helper let
    /// go of everything and exits; the host ends the session.
    Panic,
}

impl FromHelper {
    /// The 16 bytes on the pipe.
    #[must_use]
    pub fn encode(&self) -> [u8; FRAME_LEN] {
        match self {
            Self::Ready => control(KIND_READY),
            Self::Panic => control(KIND_PANIC),
        }
    }

    /// The frame `bytes` is; `None` for anything else.
    #[must_use]
    pub fn decode(bytes: &[u8; FRAME_LEN]) -> Option<Self> {
        if is_control(bytes, KIND_READY) {
            Some(Self::Ready)
        } else if is_control(bytes, KIND_PANIC) {
            Some(Self::Panic)
        } else {
            None
        }
    }
}

/// Why the helper ended; each has its own exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// The host sent [`ToHelper::Stop`].
    Stopped,
    /// The pipe closed, a read failed, or a frame was cut short.
    PipeClosed,
    /// The host's process exited.
    HostExited,
    /// No frame for [`HEARTBEAT_MISSED`].
    HeartbeatMissed,
    /// The hard cap passed.
    HardCap,
    /// The panic chord was pressed here.
    Panic,
    /// A frame that is none of the frames above (H1).
    Foreign,
    /// The command line was not `input-helper <pipe> <host pid> <cap s>`.
    BadArguments,
    /// The pipe could not be opened.
    NoPipe,
    /// The process at the other end of the pipe failed the helper's checks.
    ServerRefused,
    /// This system has no administrator helper.
    Unsupported,
}

impl Exit {
    /// The process exit code.
    #[must_use]
    pub const fn code(self) -> i32 {
        match self {
            Self::Stopped => 0,
            Self::PipeClosed => 10,
            Self::HostExited => 11,
            Self::HeartbeatMissed => 12,
            Self::HardCap => 13,
            Self::Panic => 14,
            Self::Foreign => 15,
            Self::BadArguments => 20,
            Self::NoPipe => 21,
            Self::ServerRefused => 22,
            Self::Unsupported => 23,
        }
    }

    /// The reason, in fixed words (for `sessions.log` and a console).
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Stopped => "stopped by the host",
            Self::PipeClosed => "the pipe closed",
            Self::HostExited => "the host exited",
            Self::HeartbeatMissed => "the host's heartbeat stopped",
            Self::HardCap => "the time limit passed",
            Self::Panic => "the panic key was pressed",
            Self::Foreign => "a frame that is not an input event, ReleaseAll, Stop or Heartbeat",
            Self::BadArguments => "usage: tornect input-helper <pipe> <host pid> <limit s>",
            Self::NoPipe => "the host's pipe could not be opened",
            Self::ServerRefused => {
                "the process at the other end is not this computer's Tornect host"
            }
            Self::Unsupported => "the administrator helper exists on Windows only",
        }
    }
}

/// What the helper's loop hears: frames from the pipe and the watchers'
/// news, all through one channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// A whole frame.
    Frame([u8; FRAME_LEN]),
    /// The pipe closed, a read failed, or a frame was cut short.
    Closed,
    /// The host's process exited.
    HostExited,
    /// The panic chord (physical keys only) was pressed.
    PanicChord,
}

/// The helper's clocks (§B.8.7.5 lifetime MUST).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// No frame for this long ends the helper.
    pub heartbeat: Duration,
    /// The helper never runs longer than this.
    pub hard_cap: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            heartbeat: HEARTBEAT_MISSED,
            hard_cap: HARD_CAP,
        }
    }
}

/// The helper's loop: inject the host's input events into `sink` until an
/// exit, then let go of everything (always, before returning), and on the
/// panic chord call `panicked` (which tells the host). Heartbeats and every
/// other frame restart the heartbeat clock.
pub fn run_helper<S: InputSink>(
    sink: S,
    events: &mpsc::Receiver<Event>,
    limits: Limits,
    panicked: &mut dyn FnMut(),
) -> Exit {
    let mut sink = Tracked::new(sink);
    let started = Instant::now();
    let mut heard = started;
    let exit = loop {
        let now = Instant::now();
        let cap = started + limits.hard_cap;
        let beat = heard + limits.heartbeat;
        if now >= cap {
            break Exit::HardCap;
        }
        if now >= beat {
            break Exit::HeartbeatMissed;
        }
        let event = match events.recv_timeout(cap.min(beat) - now) {
            Ok(event) => event,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break Exit::PipeClosed,
        };
        match event {
            Event::Closed => break Exit::PipeClosed,
            Event::HostExited => break Exit::HostExited,
            Event::PanicChord => break Exit::Panic,
            Event::Frame(bytes) => match ToHelper::decode(&bytes) {
                Err(_) => break Exit::Foreign,
                Ok(ToHelper::Stop) => break Exit::Stopped,
                Ok(ToHelper::Heartbeat) => heard = Instant::now(),
                Ok(ToHelper::Input(event)) => {
                    heard = Instant::now();
                    // A key the injector refuses (a system key, a failed
                    // SendInput) is not an exit: `Tracked` keeps what is owed.
                    let _ = sink.inject(&event);
                }
            },
        }
    };
    sink.release_all();
    if exit == Exit::Panic {
        panicked();
    }
    exit
}

/// Read whole frames from `read` into `events` until the pipe closes or a
/// frame is cut short ([`Event::Closed`]); for the helper's reader thread.
pub fn forward_frames(read: &mut dyn FrameRead, events: &mpsc::Sender<Event>) {
    loop {
        let event = match read.read_frame() {
            Ok(Some(frame)) => Event::Frame(frame),
            Ok(None) | Err(_) => Event::Closed,
        };
        let last = event == Event::Closed;
        if events.send(event).is_err() || last {
            return;
        }
    }
}

/// One end of the pipe, read a frame at a time.
pub trait FrameRead: Send {
    /// The next whole frame; `None` when the pipe closed cleanly between
    /// frames. A frame cut short is an error.
    fn read_frame(&mut self) -> std::io::Result<Option<[u8; FRAME_LEN]>>;
}

/// One end of the pipe, written a frame at a time, from any thread.
pub trait FrameWrite: Send + Sync {
    /// Write one frame whole.
    fn write_frame(&self, frame: &[u8; FRAME_LEN]) -> std::io::Result<()>;
    /// Close the pipe: the other end sees it closed, and a read pending on
    /// this end returns.
    fn close(&self);
}

/// `read_exact` of one frame over any reader: `None` at a clean end of
/// stream before the first byte, an error for a frame cut short.
pub fn read_frame_from(r: &mut dyn std::io::Read) -> std::io::Result<Option<[u8; FRAME_LEN]>> {
    let mut frame = [0u8; FRAME_LEN];
    let mut got = 0;
    while got < FRAME_LEN {
        match r.read(&mut frame[got..]) {
            Ok(0) if got == 0 => return Ok(None),
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "a frame cut short",
                ));
            }
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(Some(frame))
}

/// How an attached helper's link ended, for `sessions.log`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkEnd {
    /// The host stopped it (the session ended).
    Stopped,
    /// The helper said the panic chord was pressed.
    Panic,
    /// The helper went away or sent something else.
    Lost,
}

impl LinkEnd {
    /// In fixed words.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Stopped => "the session ended",
            Self::Panic => "the panic key was pressed while an administrator window had focus",
            Self::Lost => "the administrator helper stopped answering",
        }
    }
}

/// The host's end of an attached helper, and the session's injector while
/// it lives: every input event goes to the helper instead of the host's own
/// injector. A heartbeat goes out every [`HEARTBEAT_EVERY`]. Dropping it
/// sends `ReleaseAll` and [`ToHelper::Stop`] and closes the pipe. The helper's
/// [`FromHelper::Panic`], its going away and anything else it sends call
/// `ended` once (the host's kill path), unless the host stopped it first.
pub struct HelperLink {
    writer: Arc<dyn FrameWrite>,
    stopping: Arc<AtomicBool>,
    beat: Option<std::thread::JoinHandle<()>>,
    wake: Option<mpsc::Sender<()>>,
}

impl std::fmt::Debug for HelperLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HelperLink").finish_non_exhaustive()
    }
}

impl HelperLink {
    /// Attach over `writer` and `reader`, the pipe of a helper that already
    /// said [`FromHelper::Ready`]. `ended` hears how the link ended when the
    /// helper ended it (never after the host dropped the link).
    pub fn attach(
        writer: Arc<dyn FrameWrite>,
        mut reader: Box<dyn FrameRead>,
        ended: Box<dyn FnOnce(LinkEnd) + Send>,
    ) -> Self {
        let stopping = Arc::new(AtomicBool::new(false));
        let (wake, beats) = mpsc::channel::<()>();
        let beat = {
            let writer = Arc::clone(&writer);
            let stopping = Arc::clone(&stopping);
            std::thread::Builder::new()
                .name("helper-heartbeat".to_owned())
                .spawn(move || {
                    // Until the link is dropped (its sender goes) or a write fails.
                    while let Err(mpsc::RecvTimeoutError::Timeout) =
                        beats.recv_timeout(HEARTBEAT_EVERY)
                    {
                        if stopping.load(Ordering::SeqCst)
                            || writer.write_frame(&ToHelper::Heartbeat.encode()).is_err()
                        {
                            return;
                        }
                    }
                })
                .ok()
        };
        {
            let stopping = Arc::clone(&stopping);
            let writer = Arc::clone(&writer);
            let _ = std::thread::Builder::new()
                .name("helper-reader".to_owned())
                .spawn(move || {
                    let end = match reader.read_frame() {
                        Ok(Some(frame))
                            if FromHelper::decode(&frame) == Some(FromHelper::Panic) =>
                        {
                            LinkEnd::Panic
                        }
                        _ => LinkEnd::Lost,
                    };
                    // One frame is all a helper may send after `Ready`.
                    writer.close();
                    if !stopping.swap(true, Ordering::SeqCst) {
                        ended(end);
                    }
                });
        }
        Self {
            writer,
            stopping,
            beat,
            wake: Some(wake),
        }
    }

    /// Whether the helper ended the link (or the host stopped it).
    #[must_use]
    pub fn ended(&self) -> bool {
        self.stopping.load(Ordering::SeqCst)
    }
}

impl InputSink for HelperLink {
    fn inject(&mut self, event: &InputEvent) -> Result<(), InputError> {
        if self.ended() {
            return Err(InputError::Inject(
                "the administrator helper is gone".into(),
            ));
        }
        self.writer
            .write_frame(&ToHelper::Input(*event).encode())
            .map_err(|e| InputError::Inject(format!("to the administrator helper: {e}")))
    }
}

impl Drop for HelperLink {
    fn drop(&mut self) {
        let helper_ended = self.stopping.swap(true, Ordering::SeqCst);
        if !helper_ended {
            let _ = self
                .writer
                .write_frame(&ToHelper::Input(InputEvent::ReleaseAll).encode());
            let _ = self.writer.write_frame(&ToHelper::Stop.encode());
        }
        self.writer.close();
        drop(self.wake.take());
        if let Some(beat) = self.beat.take() {
            let _ = beat.join();
        }
    }
}

/// A [`FrameWrite`] over any writer, serialized by a lock.
pub struct LockedWriter<W: std::io::Write + Send> {
    inner: Mutex<Option<W>>,
    close: Box<dyn Fn(&W) + Send + Sync>,
}

impl<W: std::io::Write + Send> LockedWriter<W> {
    /// `inner`, closed by `close` (for example a socket's shutdown).
    pub fn new(inner: W, close: impl Fn(&W) + Send + Sync + 'static) -> Self {
        Self {
            inner: Mutex::new(Some(inner)),
            close: Box::new(close),
        }
    }
}

impl<W: std::io::Write + Send> FrameWrite for LockedWriter<W> {
    fn write_frame(&self, frame: &[u8; FRAME_LEN]) -> std::io::Result<()> {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        match inner.as_mut() {
            Some(w) => w.write_all(frame),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "closed",
            )),
        }
    }

    fn close(&self) {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(w) = inner.take() {
            (self.close)(&w);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Button;

    /// Records what the helper injects.
    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<InputEvent>>>);

    impl InputSink for Sink {
        fn inject(&mut self, event: &InputEvent) -> Result<(), InputError> {
            self.0.lock().unwrap().push(*event);
            Ok(())
        }
    }

    impl Sink {
        fn seen(&self) -> Vec<InputEvent> {
            self.0.lock().unwrap().clone()
        }
    }

    fn inputs() -> Vec<InputEvent> {
        vec![
            InputEvent::PointerMove { x: 1, y: 65535 },
            InputEvent::PointerButton {
                button: Button::Left,
                pressed: true,
            },
            InputEvent::PointerButton {
                button: Button::Left,
                pressed: false,
            },
            InputEvent::Wheel { dx: -120, dy: 240 },
            InputEvent::Key {
                usb: 0x07_0004,
                pressed: true,
            },
            InputEvent::Key {
                usb: 0x07_0004,
                pressed: false,
            },
            InputEvent::ReleaseAll,
        ]
    }

    /// H1: every frame kind round-trips, and only in its one encoding.
    #[test]
    fn every_frame_kind_round_trips() {
        let mut frames: Vec<ToHelper> = inputs().into_iter().map(ToHelper::Input).collect();
        frames.extend([ToHelper::Heartbeat, ToHelper::Stop]);
        for frame in frames {
            assert_eq!(ToHelper::decode(&frame.encode()).unwrap(), frame);
        }
        for frame in [FromHelper::Ready, FromHelper::Panic] {
            assert_eq!(FromHelper::decode(&frame.encode()), Some(frame));
            assert!(
                ToHelper::decode(&frame.encode()).is_err(),
                "never host to helper"
            );
        }
        assert_eq!(FromHelper::decode(&ToHelper::Stop.encode()), None);
    }

    /// H1: a foreign byte anywhere is refused — an unknown kind, a control
    /// frame with a stray byte, and an input frame in any but its canonical
    /// encoding (a field its kind does not use, set).
    #[test]
    fn a_foreign_byte_is_refused() {
        for kind in 0..=u8::MAX {
            let mut frame = [0u8; FRAME_LEN];
            frame[0] = kind;
            let known = matches!(kind, 1 | 3 | 5 | KIND_HEARTBEAT | KIND_STOP);
            assert_eq!(ToHelper::decode(&frame).is_ok(), known, "kind {kind:#x}");
        }
        for base in [
            ToHelper::Heartbeat.encode(),
            ToHelper::Stop.encode(),
            ToHelper::Input(InputEvent::ReleaseAll).encode(),
            ToHelper::Input(InputEvent::PointerButton {
                button: Button::Right,
                pressed: true,
            })
            .encode(),
            ToHelper::Input(InputEvent::Key {
                usb: 0x07_0004,
                pressed: false,
            })
            .encode(),
        ] {
            for i in 1..FRAME_LEN {
                for bit in 0..8 {
                    let mut frame = base;
                    frame[i] ^= 1 << bit;
                    if let Ok(decoded) = ToHelper::decode(&frame) {
                        // Only another valid frame, in its own encoding.
                        assert_eq!(decoded.encode(), frame, "{i}:{bit}");
                    }
                }
            }
            let mut frame = base;
            frame[12] = 0xFF;
            if matches!(frame[0], 2 | 4 | 5 | KIND_HEARTBEAT | KIND_STOP) {
                assert!(ToHelper::decode(&frame).is_err(), "an unused field set");
            }
        }
    }

    fn limits(heartbeat_ms: u64, cap_ms: u64) -> Limits {
        Limits {
            heartbeat: Duration::from_millis(heartbeat_ms),
            hard_cap: Duration::from_millis(cap_ms),
        }
    }

    fn frame(f: ToHelper) -> Event {
        Event::Frame(f.encode())
    }

    /// Every exit, each after letting go of everything held: `Stop`, the
    /// pipe's close, the host's exit, a foreign frame, the panic chord (which
    /// alone tells the host), a missed heartbeat and the hard cap.
    #[test]
    fn every_exit_lets_go_first() {
        let held = ToHelper::Input(InputEvent::Key {
            usb: 0x07_0004,
            pressed: true,
        });
        let foreign = {
            let mut f = ToHelper::Stop.encode();
            f[15] = 1;
            Event::Frame(f)
        };
        for (last, exit) in [
            (Some(frame(ToHelper::Stop)), Exit::Stopped),
            (Some(Event::Closed), Exit::PipeClosed),
            (Some(Event::HostExited), Exit::HostExited),
            (Some(foreign), Exit::Foreign),
            (Some(Event::PanicChord), Exit::Panic),
            (None, Exit::HeartbeatMissed),
        ] {
            let sink = Sink::default();
            let (tx, rx) = mpsc::channel();
            tx.send(frame(held)).unwrap();
            if let Some(last) = last {
                tx.send(last).unwrap();
            }
            let mut told = 0;
            let got = run_helper(sink.clone(), &rx, limits(150, 60_000), &mut || told += 1);
            assert_eq!(got, exit);
            assert_eq!(told, usize::from(exit == Exit::Panic), "{exit:?}");
            let seen = sink.seen();
            assert_eq!(
                seen.last(),
                Some(&InputEvent::Key {
                    usb: 0x07_0004,
                    pressed: false,
                }),
                "{exit:?}: released before the exit: {seen:?}"
            );
            assert!(exit.code() != 0 || exit == Exit::Stopped);
            assert!(!exit.reason().is_empty());
            drop(tx);
        }
        // The hard cap, although heartbeats keep coming.
        let (tx, rx) = mpsc::channel();
        let beating = std::thread::spawn(move || {
            while tx.send(frame(ToHelper::Heartbeat)).is_ok() {
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        let started = Instant::now();
        let got = run_helper(Sink::default(), &rx, limits(150, 400), &mut || {});
        assert_eq!(got, Exit::HardCap);
        assert!(started.elapsed() >= Duration::from_millis(400));
        drop(rx);
        beating.join().unwrap();
    }

    /// The heartbeat clock: frames within the limit keep the helper alive;
    /// silence past it ends it (≤ 2 s in production, 150 ms here).
    #[test]
    fn the_heartbeat_keeps_it_alive_and_its_absence_ends_it() {
        let (tx, rx) = mpsc::channel();
        let feeder = std::thread::spawn(move || {
            for _ in 0..8 {
                std::thread::sleep(Duration::from_millis(50));
                tx.send(frame(ToHelper::Heartbeat)).unwrap();
            }
            // Then silence, with the channel still open.
            std::thread::sleep(Duration::from_millis(600));
            drop(tx);
        });
        let started = Instant::now();
        let got = run_helper(Sink::default(), &rx, limits(150, 60_000), &mut || {});
        let lived = started.elapsed();
        assert_eq!(got, Exit::HeartbeatMissed);
        assert!(lived >= Duration::from_millis(400), "{lived:?}");
        assert!(lived < Duration::from_millis(900), "{lived:?}");
        feeder.join().unwrap();
        assert!(HEARTBEAT_MISSED <= Duration::from_secs(2));
        assert!(HARD_CAP <= Duration::from_secs(12 * 3600));
    }

    /// The fake pipe end to end (a Unix socket pair standing in for the
    /// Windows named pipe): the host's link sends every input event, a
    /// heartbeat each second and, when dropped, `ReleaseAll` and `Stop`; the
    /// helper injects exactly those events and exits `Stopped`.
    #[cfg(unix)]
    #[test]
    fn the_host_link_drives_the_helper_over_a_pipe() {
        use std::os::unix::net::UnixStream;

        let (host_end, helper_end) = UnixStream::pair().unwrap();
        let sink = Sink::default();
        let helper = {
            let sink = sink.clone();
            std::thread::spawn(move || {
                let (tx, rx) = mpsc::channel();
                let mut reader = helper_end.try_clone().unwrap();
                let mut writer = helper_end;
                use std::io::Write as _;
                writer.write_all(&FromHelper::Ready.encode()).unwrap();
                std::thread::spawn(move || forward_frames(&mut SocketRead(&mut reader), &tx));
                run_helper(sink, &rx, Limits::default(), &mut || {
                    let _ = writer.write_all(&FromHelper::Panic.encode());
                })
            })
        };
        let mut read = host_end.try_clone().unwrap();
        assert_eq!(
            read_frame_from(&mut read)
                .unwrap()
                .map(|f| FromHelper::decode(&f)),
            Some(Some(FromHelper::Ready))
        );
        let ended = Arc::new(Mutex::new(None));
        let mut link = {
            let ended = Arc::clone(&ended);
            let close = host_end.try_clone().unwrap();
            HelperLink::attach(
                Arc::new(LockedWriter::new(host_end, move |_| {
                    let _ = close.shutdown(std::net::Shutdown::Both);
                })),
                Box::new(SocketReader(read)),
                Box::new(move |end| *ended.lock().unwrap() = Some(end)),
            )
        };
        for event in inputs() {
            link.inject(&event).unwrap();
        }
        // Past one heartbeat: the helper hears it and stays.
        std::thread::sleep(HEARTBEAT_EVERY + Duration::from_millis(300));
        drop(link);
        assert_eq!(helper.join().unwrap(), Exit::Stopped);
        let seen = sink.seen();
        // `ReleaseAll` is kept by the helper's own tracker, never injected.
        let sent: Vec<InputEvent> = inputs()
            .into_iter()
            .filter(|e| *e != InputEvent::ReleaseAll)
            .collect();
        assert_eq!(seen, sent, "exactly the events sent, in order");
        assert_eq!(*ended.lock().unwrap(), None, "the host stopped it: no kill");
    }

    /// The helper's panic reaches the host's kill path once, and the link
    /// refuses input after it.
    #[cfg(unix)]
    #[test]
    fn the_helpers_panic_ends_the_session() {
        use std::os::unix::net::UnixStream;

        let (host_end, mut helper_end) = UnixStream::pair().unwrap();
        let ended = Arc::new(Mutex::new(Vec::new()));
        let mut link = {
            let ended = Arc::clone(&ended);
            let close = host_end.try_clone().unwrap();
            HelperLink::attach(
                Arc::new(LockedWriter::new(
                    host_end.try_clone().unwrap(),
                    move |_| {
                        let _ = close.shutdown(std::net::Shutdown::Both);
                    },
                )),
                Box::new(SocketReader(host_end)),
                Box::new(move |end| ended.lock().unwrap().push(end)),
            )
        };
        use std::io::Write as _;
        helper_end.write_all(&FromHelper::Panic.encode()).unwrap();
        for _ in 0..200 {
            if link.ended() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(link.ended());
        assert_eq!(*ended.lock().unwrap(), vec![LinkEnd::Panic]);
        assert!(
            link.inject(&InputEvent::PointerMove { x: 1, y: 1 })
                .is_err()
        );
        drop(link);
        assert_eq!(ended.lock().unwrap().len(), 1, "once");
    }

    #[cfg(unix)]
    struct SocketRead<'a>(&'a mut std::os::unix::net::UnixStream);

    #[cfg(unix)]
    impl FrameRead for SocketRead<'_> {
        fn read_frame(&mut self) -> std::io::Result<Option<[u8; FRAME_LEN]>> {
            read_frame_from(self.0)
        }
    }

    #[cfg(unix)]
    struct SocketReader(std::os::unix::net::UnixStream);

    #[cfg(unix)]
    impl FrameRead for SocketReader {
        fn read_frame(&mut self) -> std::io::Result<Option<[u8; FRAME_LEN]>> {
            read_frame_from(&mut self.0)
        }
    }
}
