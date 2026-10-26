//! The session layer's side of the direct path (the direct design §6.5,
//! §6.6, §8.5): what a stream of a session's direct QUIC connection must
//! offer [`MediaHost::serve_direct`](crate::MediaHost::serve_direct).

use std::future::Future;

use tokio::io::{AsyncRead, AsyncWrite};
use tornect_net::QuicStream;

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
