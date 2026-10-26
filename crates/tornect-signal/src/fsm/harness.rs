//! The F1 harness (`docs/PLAN.md` §B.8.15): drive either handshake FSM with
//! arbitrary frames from a peer model that behaves like a well-formed
//! counterpart as far as the transcript goes, so fuzzed bodies reach the
//! validators, the consent and accept paths and the `Established` state
//! behind valid signatures.
//!
//! The fuzz target `fuzz/fuzz_targets/envelope.rs` is a thin wrapper around
//! [`run`]; the golden-vector seeds (`fuzz/seeds/envelope/`, checked by
//! `fsm::golden`) prove that every [`Scenario`] reaches a session with the
//! recorded frames, so coverage claims about the target are testable here.
//!
//! One input byte selects the [`Scenario`] (3 bits: role, paired, re-sign);
//! the rest is [`split_frames`] into `u16`-BE length-prefixed chunks that go
//! to the FSM under test, one after another, each preceded by a drain of the
//! FSM's answers:
//!
//! * *raw* — the chunk is sent verbatim;
//! * *re-sign* — a chunk that decodes as an envelope of a signed kind is
//!   re-signed by the fixed peer key over the running transcript, which
//!   absorbs the FSM's own in-window frames exactly as a real peer would.
//!
//! The peer model never answers `ERROR` and never closes on a violation: it
//! is a dumb pipe with a transcript, so the FSM under test is the only party
//! that can end the exchange (besides the input running out). A panic inside
//! the FSM task is re-raised by [`run`], so it reaches the fuzzer (and the
//! tests) instead of vanishing into a `JoinError`.

use std::future::Future as _;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _, DuplexStream, ReadBuf, duplex};
use tornect_core::trusted::{KnownHosts, TrustedDevices};

use super::client::{ClientDeps, ClientOutcome, Intent, ScriptedClientUi, connect};
use super::host::{HostDeps, HostOutcome, serve_host};
use super::vectors::{
    self, client_config, client_identity, client_random, host_config, host_device_pk,
    host_identity, host_random,
};
use super::{Channel, HandshakeError, Taken};
use crate::envelope::Envelope;
use crate::framing::{MAX_FRAME_LEN, read_frame_max, write_frame};
use crate::pairing::{
    KnownHostStore, PairDecision, PairScript, ScriptedConsent, SessionDecision, SessionScript,
    TrustedDeviceStore,
};
use crate::transcript::{HostSigner, Transcript, sign_envelope};

/// Most frames taken from one input.
pub const MAX_FRAMES: usize = 16;

/// How long the harness waits for one more answer before it sends the next
/// frame (virtual time under `tokio::time::pause`).
pub const DRAIN: Duration = Duration::from_millis(10);

/// Which FSM is under test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The host FSM; the harness plays the client.
    Host,
    /// The client FSM; the harness plays the host.
    Client,
}

/// One of the eight harness scenarios.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scenario {
    /// The FSM under test.
    pub role: Role,
    /// Host role: the client device is pinned; client role: the host is a
    /// known host. Otherwise the PAIR path runs (consent scripted to Accept).
    pub paired: bool,
    /// Re-sign signed kinds with the peer's key over the running transcript.
    pub resign: bool,
}

impl Scenario {
    /// Decode the selector byte: bit 0 = re-sign, bit 1 = paired, bit 2 =
    /// client role (higher bits ignored).
    #[must_use]
    pub fn from_byte(b: u8) -> Self {
        Self {
            role: if b & 4 == 0 { Role::Host } else { Role::Client },
            paired: b & 2 != 0,
            resign: b & 1 != 0,
        }
    }

    /// The selector byte ([`Scenario::from_byte`] inverse).
    #[must_use]
    pub fn byte(self) -> u8 {
        u8::from(self.role == Role::Client) * 4 + u8::from(self.paired) * 2 + u8::from(self.resign)
    }

    /// Every scenario, in selector order.
    #[must_use]
    pub fn all() -> [Scenario; 8] {
        std::array::from_fn(|i| Scenario::from_byte(i as u8))
    }

    /// A short name for corpus files and reports.
    #[must_use]
    pub fn name(self) -> String {
        format!(
            "{}-{}-{}",
            match self.role {
                Role::Host => "host",
                Role::Client => "client",
            },
            if self.paired { "paired" } else { "unpaired" },
            if self.resign { "resigned" } else { "raw" },
        )
    }
}

/// Split `data` into `u16`-BE length-prefixed frames (the last one may be
/// truncated), at most [`MAX_FRAMES`].
#[must_use]
pub fn split_frames(data: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut rest = data;
    while rest.len() >= 2 && out.len() < MAX_FRAMES {
        let len = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
        rest = &rest[2..];
        let take = len.min(rest.len());
        out.push(rest[..take].to_vec());
        rest = &rest[take..];
    }
    out
}

/// The inverse of [`split_frames`] for frames under 64 KiB (seed corpora).
#[must_use]
pub fn join_frames<'a>(frames: impl IntoIterator<Item = &'a [u8]>) -> Vec<u8> {
    let mut out = Vec::new();
    for f in frames {
        let len = u16::try_from(f.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&f[..usize::from(len)]);
    }
    out
}

/// How a run ended.
#[derive(Debug)]
pub enum Outcome {
    /// The host FSM's result.
    Host(Result<HostOutcome, HandshakeError>),
    /// The client FSM's result: `Ok(true)` when a session was established
    /// (the harness then also drove `ping` and `next_event`).
    Client(Result<bool, HandshakeError>),
}

impl Outcome {
    /// Whether the FSM under test reached an established session.
    #[must_use]
    pub fn established(&self) -> bool {
        matches!(
            self,
            Outcome::Host(Ok(HostOutcome::Session { .. })) | Outcome::Client(Ok(true))
        )
    }
}

/// The harness's transcript model of a well-behaved peer.
struct Peer {
    th: Transcript,
    in_window: bool,
}

impl Peer {
    fn new(host_pk: &[u8; 32]) -> Self {
        Self {
            th: Transcript::new(host_pk),
            in_window: true,
        }
    }

    fn note(&mut self, env: &Envelope, payload: &[u8]) {
        if self.in_window && env.kind.in_handshake() {
            self.th.absorb_payload(payload);
            if env.kind.ends_handshake() {
                self.in_window = false;
            }
        }
    }

    /// A frame the FSM under test sent.
    fn observe(&mut self, payload: &[u8]) {
        if let Ok(env) = Envelope::decode(payload) {
            self.note(&env, payload);
        }
    }

    /// A frame about to be sent: re-signed when asked and the kind is signed.
    fn prepare(&mut self, signer: Option<&dyn HostSigner>, payload: Vec<u8>) -> Vec<u8> {
        let Ok(mut env) = Envelope::decode(&payload) else {
            return payload;
        };
        let bytes = match signer {
            Some(signer) if env.kind.is_signed() => {
                sign_envelope(signer, &self.th.current(), &mut env);
                env.encode()
            }
            _ => payload,
        };
        self.note(&env, &bytes);
        bytes
    }
}

/// Read everything the FSM answered until it falls silent for [`DRAIN`];
/// `false` once it closed its side.
async fn drain(stream: &mut DuplexStream, peer: &mut Peer) -> bool {
    loop {
        match tokio::time::timeout(DRAIN, read_frame_max(stream, MAX_FRAME_LEN)).await {
            Ok(Ok(Some(payload))) => peer.observe(&payload),
            Ok(Ok(None) | Err(_)) => return false,
            Err(_) => return true,
        }
    }
}

/// Feed `frames` to the FSM of `scenario` and report how it ended.
pub async fn run(scenario: Scenario, frames: Vec<Vec<u8>>) -> Outcome {
    let host = Arc::new(host_identity());
    let device = client_identity();
    let host_pk = HostSigner::public_key(&*host);
    let (a, mut b) = duplex(64 * 1024);
    let mut peer = Peer::new(&host_pk);

    match scenario.role {
        Role::Host => {
            let mut devices = TrustedDevices::default();
            if scenario.paired {
                devices.pin(device.id(), vectors::CLIENT_NAME, 1);
            }
            let consent = Arc::new(ScriptedConsent::new());
            for _ in 0..2 {
                consent.push_pairing(PairScript::Decide(PairDecision::Accept { label: None }));
                consent.push_session(SessionScript::Decide(SessionDecision::AllowOnce));
            }
            let mut deps = HostDeps::headless(
                host.clone(),
                Arc::new(TrustedDeviceStore::ephemeral(devices)),
            );
            deps.consent = consent;
            deps.random = host_random();
            let cfg = host_config();
            let task = tokio::spawn(async move { serve_host(a, &cfg, &deps).await });
            let signer: Option<&dyn HostSigner> = scenario.resign.then_some(&device);
            feed(&mut b, &mut peer, signer, frames).await;
            Outcome::Host(match task.await {
                Ok(result) => result,
                // A panic in the FSM is the finding the fuzzer exists for:
                // re-raise it instead of hiding it in the join error.
                Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
                Err(_) => Err(HandshakeError::Aborted("host task cancelled")),
            })
        }
        Role::Client => {
            let mut known = KnownHosts::default();
            if scenario.paired {
                known.pin(host.id(), vectors::HOST_NAME, host_device_pk(), 1);
            }
            let mut deps = ClientDeps::headless(Arc::new(KnownHostStore::ephemeral(known)));
            deps.ui = Arc::new(ScriptedClientUi::new(true));
            deps.random = client_random();
            let cfg = client_config(host.id());
            let task = tokio::spawn(async move {
                match connect(a, &cfg, &device, &deps, Intent::Session).await? {
                    ClientOutcome::Session(mut s) => {
                        let _ = s.ping().await;
                        let _ = s.next_event(DRAIN).await;
                        Ok(true)
                    }
                    ClientOutcome::Paired { .. } => Ok(false),
                }
            });
            let signer: Option<&dyn HostSigner> = scenario.resign.then_some(&*host);
            feed(&mut b, &mut peer, signer, frames).await;
            Outcome::Client(match task.await {
                Ok(result) => result,
                Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
                Err(_) => Err(HandshakeError::Aborted("client task cancelled")),
            })
        }
    }
}

/// Alternate draining and sending until the input or the FSM is exhausted,
/// then hang up.
async fn feed(
    stream: &mut DuplexStream,
    peer: &mut Peer,
    signer: Option<&dyn HostSigner>,
    frames: Vec<Vec<u8>>,
) {
    for frame in frames {
        if !drain(stream, peer).await {
            break;
        }
        let frame = peer.prepare(signer, frame);
        if write_frame(stream, &frame).await.is_err() {
            break;
        }
    }
    let _ = drain(stream, peer).await;
    let _ = stream.shutdown().await;
}

/// One result of [`Channel::take_frame`] in [`channel_takes`], comparable
/// across runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Took {
    /// A frame: its `msg_id` and its bytes as they were on the wire.
    Frame {
        /// The envelope's `msg_id`.
        msg_id: u64,
        /// Length prefix and payload.
        wire: Vec<u8>,
    },
    /// The stream ended at a frame boundary.
    Eof,
    /// An envelope-level fault, with its `ERROR` code.
    Fault(u16),
    /// The stream ended inside a frame.
    Truncated,
}

/// Feed `stream` to a fresh [`Channel`] (in the handshake window, or with the
/// window closed as after the accept) and collect what
/// [`Channel::take_frame`] hands out, until the end of the stream or a fault.
///
/// The reader gives out at most `cuts[i]` bytes per read (cycled; 0 counts
/// as 1) and between two reads is not ready once; at each such point the
/// pending [`Channel::frame_ready`] is dropped, as a `select!` drops it when
/// another branch wins. With `cuts` empty the stream comes in one read and is
/// never cut. The futures are polled by hand, with no runtime.
///
/// The property the cancel proptest (`fsm::channel_tests`) and the `framing`
/// fuzz target check: the result is the same for every `cuts`. It also
/// panics if the channel wrote anything (`take_frame` never writes) or held
/// more than one frame.
#[must_use]
pub fn channel_takes(stream: &[u8], cuts: &[u8], after_accept: bool) -> Vec<Took> {
    let mut chan = Channel::new(
        CutStream {
            data: stream,
            pos: 0,
            cuts,
            next_cut: 0,
            stalled: false,
            writes: 0,
        },
        &[0u8; 32],
    );
    if after_accept {
        chan.frame_cap = MAX_FRAME_LEN;
    }
    let mut cx = Context::from_waker(std::task::Waker::noop());
    let mut out = Vec::new();
    loop {
        let polled = {
            let mut ready = std::pin::pin!(chan.frame_ready());
            ready.as_mut().poll(&mut cx)
        };
        assert!(
            chan.rx.buffered() <= crate::framing::HEADER_LEN + MAX_FRAME_LEN,
            "the channel held more than one frame"
        );
        match polled {
            // Dropped while pending: the cancellation under test.
            Poll::Pending => continue,
            Poll::Ready(Err(_)) => {
                out.push(Took::Truncated);
                break;
            }
            Poll::Ready(Ok(())) => {}
        }
        match chan.take_frame() {
            Taken::Frame(rx) => out.push(Took::Frame {
                msg_id: rx.env.msg_id,
                wire: rx.wire.clone(),
            }),
            Taken::Eof => {
                out.push(Took::Eof);
                break;
            }
            Taken::Fault { code, .. } => {
                out.push(Took::Fault(code));
                break;
            }
            Taken::Pending => panic!("frame_ready resolved with nothing to take"),
        }
    }
    assert_eq!(chan.stream.writes, 0, "frame handling wrote to the stream");
    out
}

/// The reader of [`channel_takes`]: hands `data` out in cuts, stalls once
/// between two of them, and counts the writes it is asked for.
struct CutStream<'a> {
    data: &'a [u8],
    pos: usize,
    cuts: &'a [u8],
    next_cut: usize,
    stalled: bool,
    writes: usize,
}

impl AsyncRead for CutStream<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let rest = &this.data[this.pos..];
        if rest.is_empty() {
            return Poll::Ready(Ok(()));
        }
        let mut n = rest.len().min(buf.remaining());
        if !this.cuts.is_empty() {
            if !this.stalled {
                // Polled by hand: no waker to register.
                this.stalled = true;
                return Poll::Pending;
            }
            this.stalled = false;
            let cut = this.cuts[this.next_cut % this.cuts.len()].max(1);
            this.next_cut = this.next_cut.wrapping_add(1);
            n = n.min(usize::from(cut));
        }
        buf.put_slice(&rest[..n]);
        this.pos += n;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for CutStream<'_> {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        this.writes += 1;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.get_mut().writes += 1;
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scenario_bytes_roundtrip_and_frames_split() {
        for s in Scenario::all() {
            assert_eq!(Scenario::from_byte(s.byte()), s);
            assert_eq!(Scenario::from_byte(s.byte() + 8), s, "higher bits ignored");
        }
        assert_eq!(
            Scenario::from_byte(3),
            Scenario {
                role: Role::Host,
                paired: true,
                resign: true
            }
        );
        assert_eq!(Scenario::from_byte(4).name(), "client-unpaired-raw");
        let frames: Vec<&[u8]> = vec![b"ab", b"", b"xyz"];
        let joined = join_frames(frames.iter().copied());
        assert_eq!(joined, [0, 2, b'a', b'b', 0, 0, 0, 3, b'x', b'y', b'z']);
        assert_eq!(
            split_frames(&joined),
            vec![b"ab".to_vec(), vec![], b"xyz".to_vec()]
        );
        // Truncated last frame and the frame cap.
        assert_eq!(split_frames(&[0, 5, 1, 2]), vec![vec![1, 2]]);
        let many = join_frames(std::iter::repeat_n(&b"x"[..], MAX_FRAMES + 4));
        assert_eq!(split_frames(&many).len(), MAX_FRAMES);
        assert!(split_frames(&[7]).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn garbage_never_panics_and_never_establishes() {
        for s in Scenario::all() {
            let outcome = run(
                s,
                vec![vec![0xff; 3], vec![], b"\x85\x01\x01\x01\x40\xf6".to_vec()],
            )
            .await;
            assert!(!outcome.established(), "{s:?}: {outcome:?}");
        }
    }
}
