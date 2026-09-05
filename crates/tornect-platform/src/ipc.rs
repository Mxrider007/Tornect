//! The owner-only local IPC endpoint (`docs/PLAN.md` §B.8.7.4).
//!
//! ```text
//! Unix    <state_dir>/ipc.sock            0600, SO_PEERCRED uid == ours
//! Windows \\.\pipe\tornect-<hash(state)>   owner-only DACL, PIPE_REJECT_REMOTE_CLIENTS
//! ```
//!
//! This module owns the socket and the peer check, and nothing else. The
//! message types and their CBOR codec live in
//! [`tornect_core::unattended::ipc`]; the dispatch loop that turns a request
//! into a `MutationGuard` call belongs to `apps/tornect` (§B.8.14 *Ownership*).
//! Keeping those three apart is what lets fuzz target F4 exercise the codec
//! without a socket, and lets this module be tested without a guard.
//!
//! **Framing** is the §B.3 shape — `u32` big-endian length, then that many
//! bytes, at most 64 KiB — but it is implemented here rather than shared with
//! `tornect_signal::framing`. Two reasons, both deliberate: the crate direction
//! forbids `tornect-platform → tornect-signal`, and `tornect-core` carries no
//! async runtime to host a common copy. The two framings also answer to
//! different threat models — an anonymous Tor peer there, a same-uid process
//! here — so a change appropriate to one is not automatically right for the
//! other.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tornect_core::unattended::ipc::{
    IpcRequest, IpcResponse, MAX_FRAME, decode_request, decode_response, encode_request,
    encode_response,
};

/// File name of the Unix endpoint inside the state directory.
pub const SOCKET_NAME: &str = "ipc.sock";

/// How long one connection may take between frames before it is dropped.
///
/// The endpoint handles connections one at a time (see [`Endpoint::serve`]), so a client
/// that connects and then goes quiet would otherwise hold the endpoint shut.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Endpoint failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IpcError {
    /// Another host is already serving this state directory.
    #[error("another Tornect host is already running for {0}")]
    AlreadyRunning(PathBuf),
    /// No host is listening on this state directory.
    #[error("no Tornect host is running for {0}")]
    NotRunning(PathBuf),
    /// The peer is not the owner of this state directory.
    #[error("rejected an IPC peer owned by uid {peer} (endpoint belongs to uid {owner})")]
    ForeignPeer {
        /// The connecting process's uid.
        peer: u32,
        /// The uid that owns the endpoint.
        owner: u32,
    },
    /// A frame longer than [`MAX_FRAME`] was announced.
    #[error("IPC frame of {len} bytes exceeds the {MAX_FRAME}-byte limit")]
    FrameTooLarge {
        /// Announced length.
        len: usize,
    },
    /// The stream ended mid-frame.
    #[error("IPC stream ended in the middle of a frame")]
    Truncated,
    /// The peer went quiet for longer than [`IDLE_TIMEOUT`].
    #[error("IPC peer idle for more than {}s", IDLE_TIMEOUT.as_secs())]
    Idle,
    /// The frame did not decode as an IPC message.
    #[error("IPC codec: {0}")]
    Codec(#[from] tornect_core::unattended::ipc::IpcCodecError),
    /// Transport error.
    #[error("IPC I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// This platform's endpoint is not implemented yet.
    #[error("the IPC endpoint is not implemented on this platform yet ({0})")]
    Unsupported(&'static str),
}

/// The Unix socket path for a state directory.
#[must_use]
pub fn socket_path(state_dir: &Path) -> PathBuf {
    state_dir.join(SOCKET_NAME)
}

/// The Windows pipe name for a state directory (§B.8.7.4).
///
/// The state directory is hashed rather than embedded so that two
/// `TORNECT_HOME`s on one machine get distinct pipes without the path — which
/// can contain a user name — appearing in a namespace every process can list.
#[must_use]
pub fn pipe_name(state_dir: &Path) -> String {
    use sha2::{Digest as _, Sha256};
    let mut h = Sha256::new();
    h.update(state_dir.as_os_str().as_encoded_bytes());
    let digest = h.finalize();
    let hex = data_encoding::HEXLOWER.encode(&digest[..8]);
    format!(r"\\.\pipe\tornect-{hex}")
}

// ---------------------------------------------------------------------------
// framing
// ---------------------------------------------------------------------------

async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Vec<u8>>, IpcError> {
    let mut header = [0u8; 4];
    let mut filled = 0;
    while filled < header.len() {
        let n = r.read(&mut header[filled..]).await?;
        if n == 0 {
            // A clean close at a frame boundary is not an error.
            return if filled == 0 {
                Ok(None)
            } else {
                Err(IpcError::Truncated)
            };
        }
        filled += n;
    }
    let len = u32::from_be_bytes(header) as usize;
    if len > MAX_FRAME {
        // Rejected before a buffer is allocated, so an announced length can
        // never make the host reserve memory it will not use.
        return Err(IpcError::FrameTooLarge { len });
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await.map_err(|e| {
        if e.kind() == ErrorKind::UnexpectedEof {
            IpcError::Truncated
        } else {
            IpcError::Io(e)
        }
    })?;
    Ok(Some(buf))
}

async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, payload: &[u8]) -> Result<(), IpcError> {
    let len = payload.len();
    if len > MAX_FRAME {
        return Err(IpcError::FrameTooLarge { len });
    }
    let len32 = u32::try_from(len).map_err(|_| IpcError::FrameTooLarge { len })?;
    w.write_all(&len32.to_be_bytes()).await?;
    w.write_all(payload).await?;
    w.flush().await?;
    Ok(())
}

async fn with_idle_timeout<T>(
    fut: impl Future<Output = Result<T, IpcError>>,
) -> Result<T, IpcError> {
    match tokio::time::timeout(IDLE_TIMEOUT, fut).await {
        Ok(r) => r,
        Err(_) => Err(IpcError::Idle),
    }
}

// ---------------------------------------------------------------------------
// Unix
// ---------------------------------------------------------------------------

#[cfg(unix)]
mod imp {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use tokio::net::{UnixListener, UnixStream};

    use super::{
        IpcError, IpcRequest, IpcResponse, Path, PathBuf, decode_request, decode_response,
        encode_request, encode_response, read_frame, socket_path, with_idle_timeout, write_frame,
    };

    /// A bound, owner-only endpoint.
    #[derive(Debug)]
    pub struct Endpoint {
        listener: UnixListener,
        path: PathBuf,
        /// The uid that owns the socket file — by construction, ours, because
        /// this process created it. Comparing the peer's `SO_PEERCRED` uid
        /// against *this* rather than against a `getuid()` call keeps the crate
        /// free of `libc` and of `unsafe`, and asks the more precise question:
        /// "does the peer own the endpoint?" rather than "is the peer me?".
        owner_uid: u32,
    }

    impl Endpoint {
        /// Bind `<state_dir>/ipc.sock`, replacing a socket left behind by a
        /// crashed host but never one a live host is serving.
        pub async fn bind(state_dir: &Path) -> Result<Self, IpcError> {
            let path = socket_path(state_dir);
            if path.exists() {
                // A bare `exists()` cannot tell a live endpoint from a stale
                // one, and unlinking a live host's socket would silently steal
                // its CLI traffic. Connecting is the only reliable test.
                match UnixStream::connect(&path).await {
                    Ok(_) => return Err(IpcError::AlreadyRunning(state_dir.to_path_buf())),
                    Err(_) => {
                        // Refused or unreachable: nothing is listening.
                        fs_err::remove_file(&path)?;
                    }
                }
            }
            let listener = UnixListener::bind(&path)?;
            // The state directory is already 0700, so this is defence in depth
            // rather than the only barrier; the `SO_PEERCRED` check below is
            // the one that actually decides.
            fs_err::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
            let owner_uid = fs_err::metadata(&path)?.uid();
            tracing::debug!(path = %path.display(), owner_uid, "IPC endpoint bound");
            Ok(Self {
                listener,
                path,
                owner_uid,
            })
        }

        /// The bound path.
        #[must_use]
        pub fn path(&self) -> &Path {
            &self.path
        }

        /// Accept and answer requests until `handler` asks to stop or the task
        /// is dropped.
        ///
        /// Connections are handled **one at a time**, on purpose. Every op on
        /// the other side of `handler` is a `MutationGuard` call against a
        /// store that holds a single advisory lock and was never designed for
        /// concurrent mutation; serialising here removes that class of bug
        /// entirely, at a cost — one interactive CLI waiting on another — that
        /// is invisible at this traffic level. [`super::IDLE_TIMEOUT`] bounds the
        /// damage a wedged client can do.
        pub async fn serve<F, Fut>(&self, mut handler: F) -> Result<(), IpcError>
        where
            F: FnMut(IpcRequest) -> Fut,
            Fut: Future<Output = IpcResponse>,
        {
            loop {
                let (stream, _) = self.listener.accept().await?;
                if let Err(e) = self.serve_one(stream, &mut handler).await {
                    // One bad client must never take the endpoint down.
                    tracing::warn!(error = %e, "IPC connection dropped");
                }
            }
        }

        async fn serve_one<F, Fut>(
            &self,
            mut stream: UnixStream,
            handler: &mut F,
        ) -> Result<(), IpcError>
        where
            F: FnMut(IpcRequest) -> Fut,
            Fut: Future<Output = IpcResponse>,
        {
            let cred = stream.peer_cred()?;
            if cred.uid() != self.owner_uid {
                // §B.8.7.4: dropped *before any frame is read*, so a foreign
                // peer never reaches the codec.
                let e = IpcError::ForeignPeer {
                    peer: cred.uid(),
                    owner: self.owner_uid,
                };
                tracing::warn!(peer_uid = cred.uid(), peer_pid = ?cred.pid(), "{e}");
                return Err(e);
            }
            loop {
                let Some(frame) = with_idle_timeout(read_frame(&mut stream)).await? else {
                    return Ok(());
                };
                let response = match decode_request(&frame) {
                    Ok(req) => handler(req).await,
                    Err(e) => {
                        // A frame that does not decode still gets an answer, so
                        // a version-skewed CLI sees a code instead of a hang.
                        // `id` is unknown here — 0 is the documented placeholder.
                        IpcResponse::fail(0, e.code(), e.to_string())
                    }
                };
                let bytes = encode_response(&response)?;
                with_idle_timeout(write_frame(&mut stream, &bytes)).await?;
            }
        }
    }

    /// Send one request to a running host and read its answer.
    pub async fn request(state_dir: &Path, req: &IpcRequest) -> Result<IpcResponse, IpcError> {
        let path = socket_path(state_dir);
        let mut stream = UnixStream::connect(&path)
            .await
            .map_err(|_| IpcError::NotRunning(state_dir.to_path_buf()))?;
        let bytes = encode_request(req)?;
        with_idle_timeout(write_frame(&mut stream, &bytes)).await?;
        let frame = with_idle_timeout(read_frame(&mut stream))
            .await?
            .ok_or(IpcError::Truncated)?;
        Ok(decode_response(&frame)?)
    }

    /// Whether a host is serving this state directory right now.
    pub async fn is_running(state_dir: &Path) -> bool {
        UnixStream::connect(socket_path(state_dir)).await.is_ok()
    }
}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod imp {
    use super::{IpcError, IpcRequest, IpcResponse, Path};

    /// Not implemented at M1.
    #[derive(Debug)]
    pub struct Endpoint {
        _private: (),
    }

    impl Endpoint {
        /// Always fails at M1.
        ///
        /// §B.8.7.4 requires an owner-only DACL, `PIPE_REJECT_REMOTE_CLIENTS`
        /// and a verified server SID/PID on the client side. None of that is
        /// reachable without a Win32 binding (`windows-sys`), which is not
        /// pinned and cannot be verified on this dev machine — and §B.8.14
        /// schedules "IPC endpoint per OS" at M6 in any case. Returning an
        /// error is the honest M1 answer: a named pipe created without the
        /// DACL would be a *worse* outcome than none, because it would look
        /// like the endpoint works.
        pub async fn bind(_state_dir: &Path) -> Result<Self, IpcError> {
            Err(IpcError::Unsupported(
                "Windows named pipe: owner-only DACL and client SID check land at M6",
            ))
        }

        /// Unreachable at M1.
        #[must_use]
        pub fn path(&self) -> &Path {
            Path::new("")
        }

        /// Unreachable at M1.
        pub async fn serve<F, Fut>(&self, _handler: F) -> Result<(), IpcError>
        where
            F: FnMut(IpcRequest) -> Fut,
            Fut: Future<Output = IpcResponse>,
        {
            Err(IpcError::Unsupported("Windows named pipe"))
        }
    }

    /// Not implemented at M1.
    pub async fn request(state_dir: &Path, _req: &IpcRequest) -> Result<IpcResponse, IpcError> {
        let _ = state_dir;
        Err(IpcError::Unsupported("Windows named pipe"))
    }

    /// Always `false` at M1.
    pub async fn is_running(_state_dir: &Path) -> bool {
        false
    }
}

pub use imp::{Endpoint, is_running, request};

#[cfg(all(test, unix))]
mod tests {
    use tornect_core::unattended::ipc::{IpcOp, IpcRequest, IpcResponse};

    use super::*;

    fn state_dir(tmp: &tempfile::TempDir) -> PathBuf {
        let d = tmp.path().join("state");
        fs_err::create_dir_all(&d).unwrap();
        d
    }

    #[tokio::test]
    async fn a_request_round_trips_over_the_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = state_dir(&tmp);
        let ep = Endpoint::bind(&dir).await.unwrap();
        let dir2 = dir.clone();
        let server = tokio::spawn(async move {
            let _ = ep
                .serve(|req| async move {
                    assert!(matches!(req.op, IpcOp::Status));
                    IpcResponse::ok(req.id)
                })
                .await;
        });

        let resp = request(
            &dir2,
            &IpcRequest {
                id: 7,
                op: IpcOp::Status,
            },
        )
        .await
        .unwrap();
        assert_eq!(resp.id, 7);
        assert!(resp.ok);
        server.abort();
    }

    #[tokio::test]
    async fn the_socket_is_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let dir = state_dir(&tmp);
        let ep = Endpoint::bind(&dir).await.unwrap();
        let mode = fs_err::metadata(ep.path()).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "endpoint must not be group/other readable"
        );
    }

    /// A socket file left behind by a crashed host is replaced; a socket a live
    /// host is serving is not.
    #[tokio::test]
    async fn a_stale_socket_is_replaced_but_a_live_one_is_not() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = state_dir(&tmp);

        // Stale: a plain file at the socket path, nothing listening.
        fs_err::write(socket_path(&dir), b"stale").unwrap();
        let ep = Endpoint::bind(&dir).await.expect("stale socket replaced");

        // Live: a second bind against the same directory must refuse.
        let err = Endpoint::bind(&dir).await.unwrap_err();
        assert!(
            matches!(err, IpcError::AlreadyRunning(_)),
            "expected AlreadyRunning, got {err}"
        );
        drop(ep);
    }

    #[tokio::test]
    async fn connecting_to_nothing_is_not_running() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = state_dir(&tmp);
        assert!(!is_running(&dir).await);
        let err = request(
            &dir,
            &IpcRequest {
                id: 1,
                op: IpcOp::Status,
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, IpcError::NotRunning(_)), "got {err}");
    }

    /// An oversize length prefix is refused before the payload is allocated.
    #[tokio::test]
    async fn an_oversize_frame_is_refused() {
        let mut framed: Vec<u8> = Vec::new();
        framed.extend_from_slice(&u32::try_from(MAX_FRAME + 1).unwrap().to_be_bytes());
        let mut cursor = std::io::Cursor::new(framed);
        let err = read_frame(&mut cursor).await.unwrap_err();
        assert!(matches!(err, IpcError::FrameTooLarge { .. }), "got {err}");
    }

    /// A frame that does not decode is answered, not dropped: a version-skewed
    /// CLI must see a code rather than hang.
    #[tokio::test]
    async fn an_undecodable_frame_is_answered() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = state_dir(&tmp);
        let ep = Endpoint::bind(&dir).await.unwrap();
        let path = socket_path(&dir);
        let server = tokio::spawn(async move {
            let _ = ep.serve(|req| async move { IpcResponse::ok(req.id) }).await;
        });

        let mut stream = tokio::net::UnixStream::connect(&path).await.unwrap();
        write_frame(&mut stream, b"\xff\xff not cbor")
            .await
            .unwrap();
        let frame = read_frame(&mut stream).await.unwrap().expect("an answer");
        let resp = decode_response(&frame).unwrap();
        assert!(!resp.ok);
        assert_ne!(resp.code, 0);
        server.abort();
    }
}
