//! The session layer's side of the direct path (the direct design §6.5,
//! §6.6, §8.5): what a stream of a session's direct QUIC connection must
//! offer [`MediaHost::serve_direct`](crate::MediaHost::serve_direct), and
//! the viewer's one fallback after its direct `Bind`
//! ([`after_bind_close`]).

use std::future::Future;

use tokio::io::{AsyncRead, AsyncWrite};
use tornect_net::{Established, QuicStream};

/// A bidirectional stream of a session's direct connection, as the media
/// host serves it: [`tornect_net::QuicStream`] in production, a pipe in
/// tests.
pub trait DirectStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {
    /// The host's refusal of a `Bind` (the direct design §6.5): write
    /// `frame` (an encoded `BindRefused`), finish the stream, give the
    /// viewer a bounded moment to read it, then close the connection with
    /// `code`, a `tornect_proto::reason` code. Dropping the future closes at
    /// once.
    fn refuse(self, frame: Vec<u8>, code: u16) -> impl Future<Output = ()> + Send;
}

impl DirectStream for QuicStream {
    async fn refuse(self, frame: Vec<u8>, code: u16) {
        QuicStream::refuse(self, &frame, code).await;
    }
}

/// What the viewer does once [`MediaViewer::bind`](crate::MediaViewer::bind)
/// failed on the direct path ([`after_bind_close`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AfterBind {
    /// The host refused this connection's TLS handshake before sending a
    /// stream byte, so it never read the `Bind` and cannot have claimed the
    /// session: send `TOR_FALLBACK{QUIC}` and bind onion media.
    Fallback,
    /// The `Bind` may have reached the host: the commit point has passed
    /// and the session's media ends (DIRECT-2).
    End,
}

/// Whether a viewer whose direct `Bind` failed on `link` may still fall
/// back to the onion path (the direct design §4, §8.5; DIRECT-2's one
/// exception to the commit point): only when the connection was closed by a
/// TLS alert ([`Established::closed_by_crypto`]) before any host stream
/// byte arrived. Anything else — a refusal, a wrong proof, a timeout, a
/// close after the host wrote — is [`AfterBind::End`].
///
/// The direct design passes the viewer's `DirectMedia` (step A17); its
/// link is the part this reads.
#[must_use]
pub fn after_bind_close(link: &Established) -> AfterBind {
    after_close(link.closed_by_crypto(), link.stream_bytes_received())
}

/// [`after_bind_close`]'s decision from the link's two readings.
fn after_close(closed_by_crypto: bool, host_bytes: u64) -> AfterBind {
    if closed_by_crypto && host_bytes == 0 {
        AfterBind::Fallback
    } else {
        AfterBind::End
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DIRECT-2: only a TLS-alert close with no host stream byte falls
    /// back; a byte from the host, or any other close, ends the media.
    #[test]
    fn only_a_crypto_close_before_any_host_byte_falls_back() {
        assert_eq!(after_close(true, 0), AfterBind::Fallback);
        assert_eq!(after_close(true, 1), AfterBind::End);
        assert_eq!(after_close(true, 37), AfterBind::End);
        assert_eq!(after_close(false, 0), AfterBind::End);
        assert_eq!(after_close(false, 37), AfterBind::End);
    }
}
