//! The viewer's end of a services stream (the services design §6.1).
//!
//! The viewer opens the stream only when the host's signed `HELLO_ACK`
//! carries `svc1` and only after its media stream's `BindOk`, binds it with
//! a [`ServicesBinding`], and reads the host's `Welcome` (or its `Refused`).
//! [`ServicesViewer::run`] then serves it until the host closes it, the
//! viewer's session ends (its `stop`), or something breaks; its end never
//! ends the session.
//!
//! The viewer's reader applies the mirror of the host's gate: a frame only
//! the viewer sends ends the stream with `Close{PROTOCOL}`, one for a cap
//! never granted with `Close{NOT_OFFERED}`, both before the body is read. A
//! `Caps` may only take caps away; one that adds any is a protocol error.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use tokio::sync::mpsc;
use tornect_proto::services::{
    Bind, Chat, Side, SvcError, SvcMsg, Welcome, caps, read_body_max, read_header, reason,
    services_bind_mac, ty, write_msg,
};
use tornect_signal::consent::SessionToken;

use super::chat::{self, ChatGate, ChatText, sanitize_peer_text};
use super::reader::{CapState, Inbound, ReadEnd, read_frames};
use super::writer::spawn_writer;

/// Decoded frames held between the viewer's reader and its loop.
const INBOUND_DEPTH: usize = 8;

/// What the viewer binds its services stream with: the session's id and the
/// services MAC over the handshake's final transcript (§3.3). Its `Debug`
/// never prints the MAC.
#[derive(Clone)]
pub struct ServicesBinding {
    session_id: String,
    mac: [u8; 32],
}

impl ServicesBinding {
    /// The binding of the session whose token is `token` and whose handshake
    /// ended at `th_final` (`ClientSession::session_token` and `th`).
    #[must_use]
    pub fn new(token: &SessionToken, th_final: &[u8; 32]) -> Self {
        Self {
            session_id: token.session_id(),
            mac: services_bind_mac(token.bytes(), th_final),
        }
    }

    /// The session id.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// The `Bind` frame.
    pub(crate) fn msg(&self) -> SvcMsg {
        SvcMsg::Bind(Bind {
            session_id: self.session_id.clone(),
            mac: self.mac,
        })
    }
}

impl std::fmt::Debug for ServicesBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServicesBinding")
            .field("session_id", &self.session_id)
            .field("mac", &"<redacted>")
            .finish()
    }
}

/// Why a services stream did not open. The session goes on either way.
#[derive(Debug, thiserror::Error)]
pub enum ServicesBindError {
    /// The host refused: a [`reason`] code (`NOT_OFFERED` from a host with
    /// no services, `NOT_LIVE` when capture did not start, ...).
    #[error("the other computer offers no chat or files in this session (reason {0})")]
    Refused(u16),
    /// The stream failed or closed before the answer.
    #[error("the services stream failed: {0}")]
    Io(#[from] std::io::Error),
    /// No answer in time.
    #[error("no answer on the services stream in time")]
    Timeout,
    /// The answer was neither `Welcome` nor `Refused`, or malformed.
    #[error("the other computer answered the services bind with something else")]
    Protocol,
}

/// What the viewer's user asks of the services stream.
#[derive(Debug)]
pub enum ViewerOp {
    /// Write to the host's user.
    Chat(ChatText),
}

/// What [`ServicesViewer::run`] reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViewerEvent {
    /// The caps left, or the ones paused, changed.
    Caps {
        /// The caps left.
        caps: u16,
        /// The caps paused.
        paused: u16,
    },
    /// The host's user wrote, sanitised ([`sanitize_peer_text`]).
    Chat(ChatText),
    /// The stream ended with this [`reason`] code: the host's `Close`, or the
    /// viewer's own (`PROTOCOL`, `IO`). Not sent when the viewer stopped it.
    Closed(u16),
}

/// How [`ServicesViewer::run`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewerServicesEnd {
    /// `stop` resolved: `Close{SESSION_OVER}` was sent.
    Stopped,
    /// The host closed the stream with this reason.
    Closed(u16),
    /// The viewer closed it with this reason: the host broke the protocol
    /// (`PROTOCOL`), or sent a frame for a cap never granted
    /// (`NOT_OFFERED`).
    Refused(u16),
    /// The stream failed.
    Io,
}

/// A bound services stream, viewer side.
pub struct ServicesViewer<S> {
    rd: ReadHalf<S>,
    wr: WriteHalf<S>,
    welcome: Welcome,
}

impl<S> std::fmt::Debug for ServicesViewer<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServicesViewer")
            .field("welcome", &self.welcome)
            .finish_non_exhaustive()
    }
}

impl<S> ServicesViewer<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// Send the `Bind` on `stream` and wait up to `wait` for the host's
    /// answer: the stream and its `Welcome`, or why there are no services.
    /// The host answers once the session's capture is live and its caps are
    /// known, which can take its live wait and its clipboard's open.
    pub async fn bind(
        stream: S,
        binding: &ServicesBinding,
        wait: Duration,
    ) -> Result<(Self, Welcome), ServicesBindError> {
        let (mut rd, mut wr) = tokio::io::split(stream);
        write_msg(&mut wr, &binding.msg()).await.map_err(svc)?;
        let answer = tokio::time::timeout(wait, read_answer(&mut rd))
            .await
            .map_err(|_| ServicesBindError::Timeout)??;
        match answer {
            SvcMsg::Welcome(welcome) => Ok((
                Self {
                    rd,
                    wr,
                    welcome: welcome.clone(),
                },
                welcome,
            )),
            SvcMsg::Refused { reason } => Err(ServicesBindError::Refused(reason)),
            _ => Err(ServicesBindError::Protocol),
        }
    }

    /// What the host granted.
    #[must_use]
    pub fn welcome(&self) -> &Welcome {
        &self.welcome
    }

    /// Serve the stream until the host closes it, `stop` resolves (then
    /// `Close{SESSION_OVER}` is sent: the viewer's session is over), or it
    /// breaks: the user's requests come on `ops`, and what happens goes out
    /// on `events` (dropped while `events` is full: its reader is stuck,
    /// and the end is also returned).
    pub async fn run<F>(
        self,
        mut ops: mpsc::Receiver<ViewerOp>,
        events: mpsc::Sender<ViewerEvent>,
        stop: F,
    ) -> ViewerServicesEnd
    where
        F: Future<Output = ()>,
    {
        let Self { rd, wr, welcome } = self;
        let state = Arc::new(CapState::new(welcome.caps));
        let (outbox, mut writer) = spawn_writer(wr);
        let (tx, mut inbound) = mpsc::channel(INBOUND_DEPTH);
        let reader = tokio::spawn(read_frames(rd, Side::Host, Arc::clone(&state), tx));
        let mut chat_gate = ChatGate::new(chat::now());
        let emit = |event: ViewerEvent| {
            if events.try_send(event).is_err() {
                tracing::debug!("a services event was dropped: nothing reads them");
            }
        };
        tokio::pin!(stop);
        let (end, close) = loop {
            tokio::select! {
                biased;
                () = &mut stop => break (ViewerServicesEnd::Stopped, Some(reason::SESSION_OVER)),
                _ = writer.stopped() => break (ViewerServicesEnd::Io, None),
                Some(inbound) = inbound.recv() => match inbound {
                    Inbound::Frame(SvcMsg::Close { reason }) => {
                        break (ViewerServicesEnd::Closed(reason), None);
                    }
                    Inbound::Frame(SvcMsg::Caps(news)) => {
                        // Caps only shrink (§3.1): what the host turned off
                        // is skipped from now on, and it never returns.
                        if news.caps & !state.left() != 0 {
                            break (
                                ViewerServicesEnd::Refused(reason::PROTOCOL),
                                Some(reason::PROTOCOL),
                            );
                        }
                        state.turn_off(!news.caps);
                        emit(ViewerEvent::Caps {
                            caps: news.caps,
                            paused: news.paused,
                        });
                    }
                    Inbound::Frame(SvcMsg::Chat(Chat { text })) => {
                        if !chat_gate.admit(chat::now()) {
                            continue;
                        }
                        if let Some(text) = sanitize_peer_text(&text) {
                            emit(ViewerEvent::Chat(text));
                        }
                    }
                    // Served from the design's steps 14–19 on.
                    Inbound::Frame(other) => {
                        tracing::trace!(ty = other.ty(), "services frame not served by this build");
                    }
                    Inbound::End(ReadEnd::Eof | ReadEnd::Io) => break (ViewerServicesEnd::Io, None),
                    Inbound::End(ReadEnd::Refuse(code)) => {
                        break (ViewerServicesEnd::Refused(code), Some(code));
                    }
                },
                Some(op) = ops.recv() => match op {
                    ViewerOp::Chat(text) => {
                        if state.left() & caps::CHAT == 0 {
                            continue;
                        }
                        let Some(text) = text.within(usize::from(welcome.chat_max)) else {
                            continue;
                        };
                        if !outbox.ctrl(SvcMsg::Chat(Chat {
                            text: text.as_str().to_owned(),
                        })) {
                            // The host stopped reading (§3.4).
                            break (
                                ViewerServicesEnd::Refused(reason::PROTOCOL),
                                Some(reason::PROTOCOL),
                            );
                        }
                    }
                },
            }
        };
        reader.abort();
        let _ = writer.close(close).await;
        match end {
            ViewerServicesEnd::Stopped => {}
            ViewerServicesEnd::Closed(code) | ViewerServicesEnd::Refused(code) => {
                emit(ViewerEvent::Closed(code));
            }
            ViewerServicesEnd::Io => emit(ViewerEvent::Closed(reason::IO)),
        }
        end
    }
}

/// The host's answer to the `Bind`: a `Welcome` or a `Refused`, read only
/// if its type is one of the two.
async fn read_answer<R: AsyncRead + Unpin>(rd: &mut R) -> Result<SvcMsg, ServicesBindError> {
    let header = read_header(rd).await.map_err(svc)?.ok_or_else(|| {
        ServicesBindError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
    })?;
    if !matches!(header.ty, ty::WELCOME | ty::REFUSED) {
        return Err(ServicesBindError::Protocol);
    }
    let max = ty::max_body(header.ty).unwrap_or(0);
    let body = read_body_max(rd, header, max).await.map_err(svc)?;
    SvcMsg::decode(header.ty, &body).map_err(|_| ServicesBindError::Protocol)
}

fn svc(e: SvcError) -> ServicesBindError {
    match e {
        SvcError::Io(e) => ServicesBindError::Io(e),
        _ => ServicesBindError::Protocol,
    }
}
