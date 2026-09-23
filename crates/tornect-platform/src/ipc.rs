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

use std::fmt;
#[cfg(unix)]
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(unix)]
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tornect_core::unattended::ipc::{IpcRequest, IpcResponse, MAX_FRAME};
#[cfg(unix)]
use tornect_core::unattended::ipc::{
    decode_request, decode_response, encode_request, encode_response,
};
#[cfg(unix)]
use zeroize::Zeroizing;

/// File name of the Unix endpoint inside the state directory.
pub const SOCKET_NAME: &str = "ipc.sock";

/// How long a connection may sit between frames, and how long one frame may
/// take to write, before it is dropped: a client that connects and goes quiet
/// holds a connection slot, never the endpoint.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the CLI waits for the host's answer to one request.
///
/// It must outlast the slowest thing a handler does, which is an OS
/// re-authentication dialog (`reauth::PolkitReAuth::DIALOG_TIMEOUT`, 120 s),
/// plus a margin. Waiting only [`IDLE_TIMEOUT`] let the host apply an op — and,
/// for `On`, rotate in a stop code nobody saw — after the CLI had already told
/// the owner it failed (track D S1).
pub const RESPONSE_TIMEOUT: Duration = Duration::from_secs(150);

#[cfg(target_os = "linux")]
const _: () = assert!(
    RESPONSE_TIMEOUT.as_secs() >= crate::reauth::PolkitReAuth::DIALOG_TIMEOUT.as_secs() + 20,
    "the CLI must keep waiting for as long as a re-authentication dialog can stay open"
);

/// Connections served at once. Deny-direction ops must never wait behind an
/// open re-authentication dialog (§B.8.7.4: `tornect panic` always works), so
/// connections are concurrent; the bound only stops a same-uid client from
/// piling them up.
pub const MAX_CONNECTIONS: usize = 16;

/// What a handler answers with: the response, and what to undo if the response
/// never reaches the client.
pub struct Reply {
    /// The answer.
    pub response: IpcResponse,
    /// Run on the blocking pool when the answer could not be delivered (the
    /// client hung up, or stopped reading). For an op whose effect is only safe
    /// once the client has seen the answer — `On`, whose one-time stop code
    /// exists nowhere else (track D S1).
    pub on_undelivered: Option<Box<dyn FnOnce() + Send + 'static>>,
}

impl From<IpcResponse> for Reply {
    fn from(response: IpcResponse) -> Self {
        Self {
            response,
            on_undelivered: None,
        }
    }
}

impl fmt::Debug for Reply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reply")
            .field("response", &self.response)
            .field("on_undelivered", &self.on_undelivered.is_some())
            .finish()
    }
}

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
    /// The host did not answer within [`RESPONSE_TIMEOUT`].
    #[error("the Tornect host did not answer within {}s", RESPONSE_TIMEOUT.as_secs())]
    NoAnswer,
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
// framing (Unix only until the Windows named pipe lands at M6)
// ---------------------------------------------------------------------------

/// One frame. Wiped on drop: frames carry `On`'s stop code and the
/// registration's OPAQUE messages (§B.8.7.2, A14).
#[cfg(unix)]
async fn read_frame<R: AsyncRead + Unpin>(
    r: &mut R,
) -> Result<Option<Zeroizing<Vec<u8>>>, IpcError> {
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
    let mut buf = Zeroizing::new(vec![0u8; len]);
    r.read_exact(&mut buf).await.map_err(|e| {
        if e.kind() == ErrorKind::UnexpectedEof {
            IpcError::Truncated
        } else {
            IpcError::Io(e)
        }
    })?;
    Ok(Some(buf))
}

#[cfg(unix)]
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

#[cfg(unix)]
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
    use std::sync::Arc;

    use tokio::net::{UnixListener, UnixStream};
    use zeroize::Zeroize as _;

    use super::{
        IpcError, IpcRequest, IpcResponse, MAX_CONNECTIONS, Path, PathBuf, RESPONSE_TIMEOUT, Reply,
        Zeroizing, decode_request, decode_response, encode_request, encode_response, read_frame,
        socket_path, with_idle_timeout, write_frame,
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

        /// Accept and answer requests until the task is dropped.
        ///
        /// Connections are served **concurrently**, up to
        /// [`MAX_CONNECTIONS`]. They used to be served one at a time, which put
        /// `off`, `revoke`, `suspend` and `panic` behind any access-increasing
        /// op waiting on its re-authentication dialog — for up to two minutes,
        /// long enough for the CLI to give up and the op to run later anyway
        /// (track D S6). Serialising is not what keeps the store consistent: the
        /// store's own lock does that, and the guard runs the dialog without
        /// holding it. One dialog at a time is the re-auth backend's rule, not
        /// the endpoint's.
        pub async fn serve<F, Fut, R>(&self, handler: F) -> Result<(), IpcError>
        where
            F: Fn(IpcRequest) -> Fut + Clone + Send + Sync + 'static,
            Fut: Future<Output = R> + Send + 'static,
            R: Into<Reply> + Send + 'static,
        {
            let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
            loop {
                let (stream, _) = self.listener.accept().await?;
                let Ok(slot) = Arc::clone(&slots).try_acquire_owned() else {
                    // Refusing is safe: the CLI sees the connection close and
                    // reports it; nothing was run.
                    tracing::warn!(
                        max = MAX_CONNECTIONS,
                        "IPC endpoint at its connection limit; refused one"
                    );
                    continue;
                };
                let handler = handler.clone();
                let owner_uid = self.owner_uid;
                tokio::spawn(async move {
                    let _slot = slot;
                    if let Err(e) = serve_one(stream, owner_uid, &handler).await {
                        // One bad client must never take the endpoint down.
                        tracing::warn!(error = %e, "IPC connection dropped");
                    }
                });
            }
        }
    }

    async fn serve_one<F, Fut, R>(
        mut stream: UnixStream,
        owner_uid: u32,
        handler: &F,
    ) -> Result<(), IpcError>
    where
        F: Fn(IpcRequest) -> Fut,
        Fut: Future<Output = R>,
        R: Into<Reply>,
    {
        let cred = stream.peer_cred()?;
        if cred.uid() != owner_uid {
            // §B.8.7.4: dropped *before any frame is read*, so a foreign
            // peer never reaches the codec.
            let e = IpcError::ForeignPeer {
                peer: cred.uid(),
                owner: owner_uid,
            };
            tracing::warn!(peer_uid = cred.uid(), peer_pid = ?cred.pid(), "{e}");
            return Err(e);
        }
        loop {
            let Some(frame) = with_idle_timeout(read_frame(&mut stream)).await? else {
                return Ok(());
            };
            let Reply {
                mut response,
                on_undelivered,
            } = match decode_request(&frame) {
                Ok(req) => handler(req).await.into(),
                Err(e) => {
                    // A frame that does not decode still gets an answer, so
                    // a version-skewed CLI sees a code instead of a hang.
                    // `id` is unknown here — 0 is the documented placeholder.
                    IpcResponse::fail(0, e.code(), e.to_string()).into()
                }
            };
            let delivered = match encode_response(&response) {
                Ok(bytes) => {
                    let bytes = Zeroizing::new(bytes);
                    with_idle_timeout(write_frame(&mut stream, &bytes)).await
                }
                Err(e) => Err(e.into()),
            };
            // The payload may be `On`'s stop code (§B.8.7.2, A14).
            if let Some(p) = response.payload.as_mut() {
                p.zeroize();
            }
            if let Err(e) = delivered {
                if let Some(undo) = on_undelivered {
                    tracing::warn!(error = %e, "an IPC answer was not delivered; undoing its effect");
                    if let Err(join) = tokio::task::spawn_blocking(undo).await {
                        tracing::error!(error = %join, "undoing an undelivered IPC answer failed");
                    }
                }
                return Err(e);
            }
        }
    }

    /// Send one request to a running host and read its answer, waiting up to
    /// [`RESPONSE_TIMEOUT`] for it.
    pub async fn request(state_dir: &Path, req: &IpcRequest) -> Result<IpcResponse, IpcError> {
        let path = socket_path(state_dir);
        let mut stream = UnixStream::connect(&path)
            .await
            .map_err(|_| IpcError::NotRunning(state_dir.to_path_buf()))?;
        let bytes = Zeroizing::new(encode_request(req)?);
        with_idle_timeout(write_frame(&mut stream, &bytes)).await?;
        // Not the idle bound: the host may be showing the owner an OS dialog.
        let frame = match tokio::time::timeout(RESPONSE_TIMEOUT, read_frame(&mut stream)).await {
            Ok(frame) => frame?.ok_or(IpcError::Truncated)?,
            Err(_) => return Err(IpcError::NoAnswer),
        };
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
    use super::{IpcError, IpcRequest, IpcResponse, Path, Reply};

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
        pub async fn serve<F, Fut, R>(&self, _handler: F) -> Result<(), IpcError>
        where
            F: Fn(IpcRequest) -> Fut + Clone + Send + Sync + 'static,
            Fut: Future<Output = R> + Send + 'static,
            R: Into<Reply> + Send + 'static,
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
    use std::sync::Arc;

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

    /// Track D S1: an answer that takes longer than [`IDLE_TIMEOUT`] — the owner
    /// taking 90 s over the host's re-authentication dialog — still reaches the
    /// CLI. The CLI used to give up at 30 s and report failure while the host went
    /// on to apply the op (virtual time: the test does not wait 90 s).
    #[tokio::test(start_paused = true)]
    async fn an_answer_may_take_as_long_as_a_reauth_dialog() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = state_dir(&tmp);
        let ep = Endpoint::bind(&dir).await.unwrap();
        let server = tokio::spawn(async move {
            let _ = ep
                .serve(|req: IpcRequest| async move {
                    tokio::time::sleep(IDLE_TIMEOUT + Duration::from_secs(60)).await;
                    IpcResponse::ok(req.id)
                })
                .await;
        });
        let resp = request(
            &dir,
            &IpcRequest {
                id: 9,
                op: IpcOp::On,
            },
        )
        .await
        .expect("the answer must arrive, however long the dialog took");
        assert!(resp.ok);
        assert_eq!(resp.id, 9);
        server.abort();
    }

    /// Track D S1, host side: an answer the client never received runs its undo
    /// (a CLI killed while the dialog was up must not leave `On` applied with a
    /// stop code nobody saw).
    #[tokio::test]
    async fn an_undelivered_answer_runs_its_undo() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = state_dir(&tmp);
        let ep = Endpoint::bind(&dir).await.unwrap();
        let hung_up = Arc::new(tokio::sync::Notify::new());
        let (undone_tx, mut undone_rx) = tokio::sync::mpsc::unbounded_channel::<u64>();
        let h = Arc::clone(&hung_up);
        let server = tokio::spawn(async move {
            let _ = ep
                .serve(move |req: IpcRequest| {
                    let h = Arc::clone(&h);
                    let tx = undone_tx.clone();
                    async move {
                        h.notified().await;
                        let id = req.id;
                        Reply {
                            response: IpcResponse::ok(id),
                            on_undelivered: Some(Box::new(move || {
                                let _ = tx.send(id);
                            })),
                        }
                    }
                })
                .await;
        });

        let mut stream = tokio::net::UnixStream::connect(socket_path(&dir))
            .await
            .unwrap();
        let bytes = encode_request(&IpcRequest {
            id: 5,
            op: IpcOp::On,
        })
        .unwrap();
        write_frame(&mut stream, &bytes).await.unwrap();
        drop(stream);
        hung_up.notify_one();

        let undone = tokio::time::timeout(Duration::from_secs(10), undone_rx.recv())
            .await
            .expect("the undo must run once the answer cannot be written");
        assert_eq!(undone, Some(5));
        server.abort();
    }

    /// Track D S6: a request is answered while another client's request is still
    /// waiting on its (simulated) re-authentication dialog. The serial endpoint
    /// made `off`, `revoke` and `panic` queue behind the dialog.
    #[tokio::test]
    async fn a_request_does_not_wait_behind_a_pending_dialog() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = state_dir(&tmp);
        let ep = Endpoint::bind(&dir).await.unwrap();
        let entered = Arc::new(tokio::sync::Notify::new());
        let dialog = Arc::new(tokio::sync::Notify::new());
        let (e, d) = (Arc::clone(&entered), Arc::clone(&dialog));
        let server = tokio::spawn(async move {
            let _ = ep
                .serve(move |req: IpcRequest| {
                    let (e, d) = (Arc::clone(&e), Arc::clone(&d));
                    async move {
                        if matches!(req.op, IpcOp::On) {
                            e.notify_one();
                            d.notified().await;
                        }
                        IpcResponse::ok(req.id)
                    }
                })
                .await;
        });

        let dir_on = dir.clone();
        let pending = tokio::spawn(async move {
            request(
                &dir_on,
                &IpcRequest {
                    id: 1,
                    op: IpcOp::On,
                },
            )
            .await
        });
        entered.notified().await;
        let off = tokio::time::timeout(
            Duration::from_secs(10),
            request(
                &dir,
                &IpcRequest {
                    id: 2,
                    op: IpcOp::Off,
                },
            ),
        )
        .await
        .expect("`off` must not wait behind a pending re-authentication dialog")
        .unwrap();
        assert!(off.ok);

        dialog.notify_one();
        assert!(
            pending.await.unwrap().unwrap().ok,
            "the pending op still completes"
        );
        server.abort();
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
