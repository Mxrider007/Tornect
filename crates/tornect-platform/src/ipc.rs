//! The owner-only local IPC endpoint (`docs/PLAN.md` §B.8.7.4).
//!
//! ```text
//! Unix    <state_dir>/ipc.sock            0600, SO_PEERCRED uid == ours
//! Windows \\.\pipe\tornect-ctl-<32 hex>    a name drawn from 128 random bits at each
//!                                         host start, written once the pipe exists
//!                                         into <state_dir>\ipc.pipe (this account
//!                                         only), from which the command line reads
//!                                         it; explicit DACL (this account only), the
//!                                         first instance FILE_FLAG_FIRST_PIPE_INSTANCE,
//!                                         PIPE_REJECT_REMOTE_CLIENTS, each end checks
//!                                         the other's account (SID, from its PID)
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
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tornect_core::unattended::ipc::{
    IpcRequest, IpcResponse, MAX_FRAME, decode_request, decode_response, encode_request,
    encode_response,
};
use zeroize::{Zeroize as _, Zeroizing};

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
    /// Windows: the control channel's pipe already exists, made by another
    /// process before this host; it is never used (§B.8.7.4).
    #[error("the control channel's pipe already exists (another process made it first)")]
    NameTaken,
    /// Windows: the process at the other end of the pipe runs as another
    /// account, or its account could not be read.
    #[error("rejected an IPC peer (process {pid}) that is not of this account")]
    ForeignAccount {
        /// The other end's process id.
        pid: u32,
    },
    /// Windows: the control channel's name file holds anything but a control
    /// pipe's name; no pipe was opened (§B.8.7.4).
    #[error("the control channel's name file is not one Tornect wrote; no host was asked")]
    NameFile,
}

/// The Unix socket path for a state directory.
#[must_use]
pub fn socket_path(state_dir: &Path) -> PathBuf {
    state_dir.join(SOCKET_NAME)
}

/// File name, inside the state directory, of the Windows control pipe's name
/// (§B.8.7.4): written by the host once its pipe exists, with a descriptor
/// that admits this account alone, and read by the command line.
pub const PIPE_NAME_FILE: &str = "ipc.pipe";

/// Every control pipe's name starts so; 32 lowercase hex digits follow. It is
/// not the administrator helper's prefix (`helper::PIPE_PREFIX`).
#[cfg(any(windows, test))]
const CONTROL_PIPE_PREFIX: &str = r"\\.\pipe\tornect-ctl-";

/// The most the command line reads of the name file; a name is 53 bytes.
#[cfg(any(windows, test))]
const NAME_FILE_MAX: u64 = 128;

/// The control pipe's name for 16 random bytes (§B.8.7.4). It is drawn afresh
/// at each host start and never computed from the state directory, so another
/// account can neither predict it nor create the pipe first, and no part of
/// the path appears in a namespace every process can list.
#[cfg(any(windows, test))]
fn control_pipe_name(random: &[u8; 16]) -> String {
    let mut name = String::with_capacity(CONTROL_PIPE_PREFIX.len() + 32);
    name.push_str(CONTROL_PIPE_PREFIX);
    name.push_str(&data_encoding::HEXLOWER.encode(random));
    name
}

/// A fresh control pipe name: 128 bits from the system's random source.
#[cfg(any(windows, test))]
fn new_control_pipe_name() -> std::io::Result<String> {
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).map_err(|e| std::io::Error::other(e.to_string()))?;
    Ok(control_pipe_name(&random))
}

/// Whether `name` is exactly a control pipe's name as [`control_pipe_name`]
/// writes it: this machine's pipes, the control prefix and 32 lowercase hex
/// digits, and nothing before or after them.
#[cfg(any(windows, test))]
fn valid_control_pipe_name(name: &str) -> bool {
    name.strip_prefix(CONTROL_PIPE_PREFIX).is_some_and(|hex| {
        hex.len() == 32 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

/// The control pipe's name, read from the name file of `state_dir` (at most
/// [`NAME_FILE_MAX`] bytes): no file means no host ([`IpcError::NotRunning`]);
/// anything but exactly a control pipe's name is refused
/// ([`IpcError::NameFile`]) and never taken for a running host.
#[cfg(any(windows, test))]
fn read_pipe_name(state_dir: &Path) -> Result<String, IpcError> {
    use std::io::Read as _;
    let file = match std::fs::File::open(state_dir.join(PIPE_NAME_FILE)) {
        Ok(file) => file,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            return Err(IpcError::NotRunning(state_dir.to_path_buf()));
        }
        Err(e) => return Err(e.into()),
    };
    let mut bytes = Vec::new();
    file.take(NAME_FILE_MAX).read_to_end(&mut bytes)?;
    match std::str::from_utf8(&bytes) {
        Ok(name) if valid_control_pipe_name(name) => Ok(name.to_owned()),
        _ => Err(IpcError::NameFile),
    }
}

/// Write `name` into the name file of `state_dir` in one replacement: a new
/// temporary file beside it, made by `create_new` (on Windows with the pipe's
/// this-account-only descriptor), written and flushed, then moved over the
/// name file by `replace`. On any failure the temporary file is removed and
/// the name file is left as it was.
#[cfg(any(windows, test))]
fn write_pipe_name(
    state_dir: &Path,
    name: &str,
    create_new: impl FnOnce(&Path) -> std::io::Result<std::fs::File>,
    replace: impl FnOnce(&Path, &Path) -> std::io::Result<()>,
) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut random = [0u8; 8];
    getrandom::fill(&mut random).map_err(|e| std::io::Error::other(e.to_string()))?;
    let tmp = state_dir.join(format!(
        "{PIPE_NAME_FILE}.{}.tmp",
        data_encoding::HEXLOWER.encode(&random)
    ));
    let mut file = create_new(&tmp)?;
    let mut written = file
        .write_all(name.as_bytes())
        .and_then(|()| file.sync_all());
    drop(file);
    if written.is_ok() {
        written = replace(&tmp, &state_dir.join(PIPE_NAME_FILE));
    }
    if written.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    written
}

/// Remove the name file of `state_dir` if it still names `name`: a host that
/// stops takes its own name away, never one written after it.
#[cfg(any(windows, test))]
fn remove_pipe_name(state_dir: &Path, name: &str) {
    if read_pipe_name(state_dir).is_ok_and(|current| current == name) {
        let _ = std::fs::remove_file(state_dir.join(PIPE_NAME_FILE));
    }
}

/// The Windows control channel's bind, in its order (§B.8.7.4): a fresh name
/// from `new_name`; the pipe's first instance under it (`create_first`), a pipe
/// that already exists refused before any file is touched ([`claim_first`]);
/// then the name written into the name file through `create_new` and `replace`
/// ([`write_pipe_name`]). A name that could not be written means no channel,
/// and a name file left by an earlier host is removed, best effort. The name
/// and the first instance.
#[cfg(any(windows, test))]
fn bind_steps<P>(
    state_dir: &Path,
    new_name: impl FnOnce() -> std::io::Result<String>,
    create_first: impl FnOnce(&str) -> std::io::Result<P>,
    create_new: impl FnOnce(&Path) -> std::io::Result<std::fs::File>,
    replace: impl FnOnce(&Path, &Path) -> std::io::Result<()>,
) -> Result<(String, P), IpcError> {
    let name = new_name()?;
    let first = claim_first(create_first(&name))?;
    if let Err(e) = write_pipe_name(state_dir, &name, create_new, replace) {
        let _ = std::fs::remove_file(state_dir.join(PIPE_NAME_FILE));
        return Err(e.into());
    }
    Ok((name, first))
}

// ---------------------------------------------------------------------------
// framing (both endpoints)
// ---------------------------------------------------------------------------

/// One frame. Wiped on drop: frames carry `On`'s stop code and the
/// registration's OPAQUE messages (§B.8.7.2, A14).
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

/// Answer `stream`'s requests with `handler` until the client closes it: one
/// connection of either endpoint, after its peer check.
async fn serve_frames<S, F, Fut, R>(stream: &mut S, handler: &F) -> Result<(), IpcError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: Fn(IpcRequest) -> Fut,
    Fut: Future<Output = R>,
    R: Into<Reply>,
{
    loop {
        let Some(frame) = with_idle_timeout(read_frame(stream)).await? else {
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
                with_idle_timeout(write_frame(stream, &bytes)).await
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

/// Send `req` on `stream` and read its answer, waiting up to
/// [`RESPONSE_TIMEOUT`] for it (the host may be showing the owner an OS
/// dialog).
async fn exchange<S>(stream: &mut S, req: &IpcRequest) -> Result<IpcResponse, IpcError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let bytes = Zeroizing::new(encode_request(req)?);
    with_idle_timeout(write_frame(stream, &bytes)).await?;
    // Not the idle bound: the host may be showing the owner an OS dialog.
    let frame = match tokio::time::timeout(RESPONSE_TIMEOUT, read_frame(stream)).await {
        Ok(frame) => frame?.ok_or(IpcError::Truncated)?,
        Err(_) => return Err(IpcError::NoAnswer),
    };
    Ok(decode_response(&frame)?)
}

/// The pause before the endpoint tries again after a failure that leaves it
/// standing (audit B17): an `accept` that failed (the descriptor limit, a
/// passing shortage of memory or buffers, a connection aborted before it was
/// taken), or a Windows pipe instance that could not be made or freed. 50 ms,
/// doubling to at most 1 s; back to 50 ms once a connection is accepted. One
/// such failure used to end the endpoint, and with it `tornect panic`, the
/// second launch's Show and every `tornect unattended` command, until the
/// host restarted.
#[derive(Debug)]
struct Backoff {
    next: Duration,
}

impl Backoff {
    const FIRST: Duration = Duration::from_millis(50);
    const MAX: Duration = Duration::from_secs(1);

    fn new() -> Self {
        Self { next: Self::FIRST }
    }

    /// The pause after one more failure.
    fn failed(&mut self) -> Duration {
        let pause = self.next;
        self.next = (self.next * 2).min(Self::MAX);
        pause
    }

    /// A connection was accepted: the next failure pauses briefly again.
    #[cfg(any(unix, test))]
    fn succeeded(&mut self) {
        self.next = Self::FIRST;
    }
}

/// `make`, tried until it works, with a [`Backoff`] pause after each failure
/// (logged as `what`): the Windows endpoint's next pipe instance, made while
/// the caller still holds one, so the pipe's name never lapses while it waits.
#[cfg(any(windows, test))]
async fn until_made<T, E: fmt::Display>(what: &str, mut make: impl FnMut() -> Result<T, E>) -> T {
    let mut backoff = Backoff::new();
    loop {
        match make() {
            Ok(made) => return made,
            Err(e) => {
                let pause = backoff.failed();
                tracing::warn!(error = %e, retry_in = ?pause, "{what} failed; trying again");
                tokio::time::sleep(pause).await;
            }
        }
    }
}

/// Whether an `accept` error means the listening socket itself is unusable
/// (`EBADF`, `EINVAL`, `ENOTSOCK`), which ends the endpoint. Every other one
/// is about one connection or a passing shortage (`EMFILE` and `ENFILE` at
/// the descriptor limit, `ENOBUFS`, `ENOMEM`, `ECONNABORTED`, `EINTR`,
/// `EPERM`, `EPROTO`): the endpoint pauses ([`Backoff`]) and accepts again.
/// The numbers are the kernel's (no `libc` here): the same on Linux, macOS
/// and the BSDs but for `ENOTSOCK`.
#[cfg(unix)]
fn listener_is_gone(e: &std::io::Error) -> bool {
    const EBADF: i32 = 9;
    const EINVAL: i32 = 22;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    const ENOTSOCK: i32 = 88;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    const ENOTSOCK: i32 = 38;
    matches!(e.raw_os_error(), Some(EBADF | EINVAL | ENOTSOCK))
}

/// `ERROR_ACCESS_DENIED`: what `FILE_FLAG_FIRST_PIPE_INSTANCE` fails with when
/// the pipe exists.
#[cfg(any(windows, test))]
const PIPE_EXISTS: i32 = 5;
/// `ERROR_PIPE_BUSY`: the pipe exists and has all its instances.
#[cfg(any(windows, test))]
const PIPE_FULL: i32 = 231;

/// The Windows pipe's first instance, or no channel (§B.8.7.4): a pipe that
/// already exists — made first by another process — is never used.
#[cfg(any(windows, test))]
fn claim_first<T>(created: std::io::Result<T>) -> Result<T, IpcError> {
    created.map_err(|e| match e.raw_os_error() {
        Some(PIPE_EXISTS | PIPE_FULL) => IpcError::NameTaken,
        _ => IpcError::Io(e),
    })
}

/// The Windows pipe's peer check, at both ends (§B.8.7.4): the process `pid`
/// at the other end runs as this account (`own`, a string SID), or the
/// connection ends before a frame is read or sent; an account that could not
/// be read is refused too.
#[cfg(any(windows, test))]
fn check_account(peer: std::io::Result<String>, own: &str, pid: u32) -> Result<(), IpcError> {
    match peer {
        Ok(account) if account == own => Ok(()),
        Ok(_) | Err(_) => {
            let e = IpcError::ForeignAccount { pid };
            tracing::warn!("{e}");
            Err(e)
        }
    }
}

/// Whether the command line takes the Windows pipe its name file names for a running host
/// (§B.8.7.4), from what opening it gave (`opened`) and the check of its server's account
/// (`server_is_ours`, the check `request` makes before anything is sent): a pipe it opened
/// counts only when that check passes. A name file left by a host that did not stop
/// cleanly can name a pipe another account made since; that pipe, or one whose server's
/// account cannot be read, is no host, so the command line falls to the host lock. A pipe
/// whose every instance is busy counts; no name file, no pipe of that name or a name file
/// that is not one is no host.
#[cfg(any(windows, test))]
fn running<P>(
    opened: Result<P, IpcError>,
    server_is_ours: impl FnOnce(&P) -> Result<(), IpcError>,
) -> bool {
    match opened {
        Ok(pipe) => server_is_ours(&pipe).is_ok(),
        Err(IpcError::Io(e)) => e.raw_os_error() == Some(PIPE_FULL),
        Err(_) => false,
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

    use super::{
        Backoff, IpcError, IpcRequest, IpcResponse, MAX_CONNECTIONS, Path, PathBuf, Reply,
        exchange, listener_is_gone, serve_frames, socket_path,
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
        ///
        /// An `accept` that fails pauses the loop and is tried again
        /// ([`Backoff`], audit B17); only a listening socket that is itself
        /// unusable ends it, with that error.
        pub async fn serve<F, Fut, R>(&self, handler: F) -> Result<(), IpcError>
        where
            F: Fn(IpcRequest) -> Fut + Clone + Send + Sync + 'static,
            Fut: Future<Output = R> + Send + 'static,
            R: Into<Reply> + Send + 'static,
        {
            accept_loop(&self.listener, self.owner_uid, handler).await
        }
    }

    /// Where connections come from: the endpoint's listener, or a test's.
    pub(super) trait Accept {
        /// The next connection.
        fn next_connection(&self) -> impl Future<Output = std::io::Result<UnixStream>> + Send;
    }

    impl Accept for UnixListener {
        async fn next_connection(&self) -> std::io::Result<UnixStream> {
            self.accept().await.map(|(stream, _)| stream)
        }
    }

    /// [`Endpoint::serve`]'s loop over `listener`, whose socket file
    /// `owner_uid` owns.
    pub(super) async fn accept_loop<L, F, Fut, R>(
        listener: &L,
        owner_uid: u32,
        handler: F,
    ) -> Result<(), IpcError>
    where
        L: Accept + Sync,
        F: Fn(IpcRequest) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = R> + Send + 'static,
        R: Into<Reply> + Send + 'static,
    {
        let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
        let mut backoff = Backoff::new();
        loop {
            let stream = match listener.next_connection().await {
                Ok(stream) => {
                    backoff.succeeded();
                    stream
                }
                Err(e) if listener_is_gone(&e) => return Err(e.into()),
                Err(e) => {
                    let pause = backoff.failed();
                    tracing::warn!(
                        error = %e,
                        retry_in = ?pause,
                        "the IPC endpoint could not accept a connection; trying again"
                    );
                    tokio::time::sleep(pause).await;
                    continue;
                }
            };
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
            tokio::spawn(async move {
                let _slot = slot;
                if let Err(e) = serve_one(stream, owner_uid, &handler).await {
                    // One bad client must never take the endpoint down.
                    tracing::warn!(error = %e, "IPC connection dropped");
                }
            });
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
        serve_frames(&mut stream, handler).await
    }

    /// Send one request to a running host and read its answer, waiting up to
    /// [`RESPONSE_TIMEOUT`](super::RESPONSE_TIMEOUT) for it.
    pub async fn request(state_dir: &Path, req: &IpcRequest) -> Result<IpcResponse, IpcError> {
        let path = socket_path(state_dir);
        let mut stream = UnixStream::connect(&path)
            .await
            .map_err(|_| IpcError::NotRunning(state_dir.to_path_buf()))?;
        exchange(&mut stream, req).await
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
#[allow(unsafe_code)] // the pipe's descriptor, its name file and its peers' accounts: FFI, each block below says why it is sound
mod imp {
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
    use std::ptr::null_mut;
    use std::sync::{Arc, Mutex, PoisonError};
    use std::time::{Duration, Instant};

    use tokio::net::windows::named_pipe::{
        ClientOptions, NamedPipeClient, NamedPipeServer, PipeMode, ServerOptions,
    };
    use windows_sys::Win32::Foundation::{
        ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, GENERIC_WRITE, HANDLE, HLOCAL, INVALID_HANDLE_VALUE,
        LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY};
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, MOVEFILE_REPLACE_EXISTING,
        MOVEFILE_WRITE_THROUGH, MoveFileExW, SECURITY_IDENTIFICATION,
    };
    use windows_sys::Win32::System::Pipes::{
        GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    use super::{
        IDLE_TIMEOUT, IpcError, IpcRequest, IpcResponse, MAX_CONNECTIONS, Path, PathBuf, Reply,
        bind_steps, check_account, exchange, new_control_pipe_name, read_pipe_name,
        remove_pipe_name, running, serve_frames, until_made,
    };
    use crate::win::{OwnedHandle, current_user_sid, sid_of, sid_string, token_user, wide};

    /// How long a client waits for a free instance while every one is busy.
    const BUSY_WAIT: Duration = Duration::from_millis(50);

    /// The pipe's security descriptor: an explicit, protected DACL that admits
    /// this account alone (`D:P(A;;GA;;;<SID>)`), never the default descriptor.
    struct Descriptor(PSECURITY_DESCRIPTOR);

    // SAFETY: the descriptor is memory this value owns alone (allocated by the
    // conversion below, freed once on drop) and is only read after creation.
    unsafe impl Send for Descriptor {}
    // SAFETY: as above: nothing writes to it after creation.
    unsafe impl Sync for Descriptor {}

    impl Descriptor {
        fn this_account_only(user_sid: &str) -> std::io::Result<Self> {
            let text = wide(crate::helper::pipe_sddl(user_sid, false));
            let mut sd: PSECURITY_DESCRIPTOR = null_mut();
            // SAFETY: `text` is NUL-terminated; on success `sd` receives a
            // descriptor allocated with `LocalAlloc`, freed on drop.
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    text.as_ptr(),
                    SDDL_REVISION_1,
                    &mut sd,
                    null_mut(),
                )
            };
            if ok == 0 || sd.is_null() {
                return Err(std::io::Error::last_os_error());
            }
            Ok(Self(sd))
        }
    }

    impl Drop for Descriptor {
        fn drop(&mut self) {
            // SAFETY: allocated by the conversion above, freed once.
            unsafe { LocalFree(self.0 as HLOCAL) };
        }
    }

    /// One server instance of `name` with `descriptor`: the first one with
    /// `FILE_FLAG_FIRST_PIPE_INSTANCE` (a pipe that already exists fails it),
    /// remote clients refused, at most one instance per connection served plus
    /// the one waiting.
    fn instance(
        name: &str,
        descriptor: &Descriptor,
        first: bool,
    ) -> std::io::Result<NamedPipeServer> {
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        let mut options = ServerOptions::new();
        options
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .pipe_mode(PipeMode::Byte)
            .max_instances(MAX_CONNECTIONS + 1);
        // SAFETY: `attributes` points at the live descriptor, and both outlive
        // the call, which copies what it needs.
        unsafe { options.create_with_security_attributes_raw(name, (&raw mut attributes).cast()) }
    }

    /// A new file at `path` (it must not exist) with `descriptor`, open for
    /// writing and shared with nobody: the name file's temporary copy.
    fn create_owner_only(path: &Path, descriptor: &Descriptor) -> std::io::Result<std::fs::File> {
        let name = wide(path);
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        // SAFETY: `name` is NUL-terminated; `attributes` points at the live
        // descriptor, and both outlive the call; no template handle.
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_WRITE,
                0,
                &raw const attributes,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `handle` is a file handle this call just opened and owns
        // alone; the `File` closes it once, on drop.
        Ok(unsafe { std::fs::File::from_raw_handle(handle) })
    }

    /// Move `from` over `to`, replacing it (`MoveFileExW`); the moved file
    /// keeps its descriptor.
    fn replace_file(from: &Path, to: &Path) -> std::io::Result<()> {
        let (from, to) = (wide(from), wide(to));
        // SAFETY: both names are NUL-terminated and outlive the call.
        let ok = unsafe {
            MoveFileExW(
                from.as_ptr(),
                to.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// The account (string SID) process `pid` runs as.
    fn account_of(pid: u32) -> std::io::Result<String> {
        // SAFETY: plain call; a null result is an error, a handle is closed by
        // `OwnedHandle`.
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if process.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let process = OwnedHandle(process);
        let mut token: HANDLE = null_mut();
        // SAFETY: `process` is open; `token` receives a handle on success.
        if unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut token) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let token = OwnedHandle(token);
        let user = token_user(token.0)?;
        sid_string(sid_of(&user))
    }

    /// The process id of the client connected to `pipe`.
    fn client_pid(pipe: &NamedPipeServer) -> std::io::Result<u32> {
        let mut pid = 0u32;
        // SAFETY: the handle is the open pipe's; `pid` is writable.
        if unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle(), &mut pid) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(pid)
    }

    /// The process id of the server `pipe` is connected to.
    fn server_pid(pipe: &NamedPipeClient) -> std::io::Result<u32> {
        let mut pid = 0u32;
        // SAFETY: the handle is the open pipe's; `pid` is writable.
        if unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut pid) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(pid)
    }

    /// The bound endpoint: `\\.\pipe\tornect-ctl-<32 hex>`, a fresh random
    /// name, its first instance created by this process and the name written
    /// into the state directory's name file, which the endpoint removes when
    /// dropped if it still holds this name.
    pub struct Endpoint {
        name: String,
        path: PathBuf,
        state_dir: PathBuf,
        account: String,
        descriptor: Descriptor,
        waiting: Mutex<Option<NamedPipeServer>>,
    }

    impl Drop for Endpoint {
        fn drop(&mut self) {
            remove_pipe_name(&self.state_dir, &self.name);
        }
    }

    impl std::fmt::Debug for Endpoint {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Endpoint")
                .field("name", &self.name)
                .finish_non_exhaustive()
        }
    }

    impl Endpoint {
        /// Create the pipe's first instance under a fresh random name
        /// (§B.8.7.4): the explicit DACL, and `FILE_FLAG_FIRST_PIPE_INSTANCE`,
        /// so a pipe another process made first is never used: no channel then
        /// ([`IpcError::NameTaken`]). Then the name is written into
        /// `<state_dir>\ipc.pipe` with the same descriptor; a name that could
        /// not be written means no channel either, and a name file left by an
        /// earlier host is removed, best effort.
        pub async fn bind(state_dir: &Path) -> Result<Self, IpcError> {
            let account = current_user_sid()?;
            let descriptor = Descriptor::this_account_only(&account)?;
            let (name, first) = bind_steps(
                state_dir,
                new_control_pipe_name,
                |name| instance(name, &descriptor, true),
                |tmp| create_owner_only(tmp, &descriptor),
                replace_file,
            )?;
            tracing::debug!(%name, "IPC endpoint bound");
            Ok(Self {
                path: PathBuf::from(&name),
                name,
                state_dir: state_dir.to_path_buf(),
                account,
                descriptor,
                waiting: Mutex::new(Some(first)),
            })
        }

        /// The pipe's name.
        #[must_use]
        pub fn path(&self) -> &Path {
            &self.path
        }

        /// Accept and answer requests until the task is dropped, up to
        /// [`MAX_CONNECTIONS`] at once, as the Unix endpoint does (track D S6:
        /// `off`, `revoke` and `panic` never wait behind another request's
        /// re-authentication dialog). The next instance is created before a
        /// connected one is handed over, so the name never lapses; one that
        /// cannot be made yet (every instance taken while a finished
        /// connection's handle is still closing, a passing shortage of
        /// resources) is tried again after a pause while the connected one
        /// waits, and an instance that cannot be freed after a refusal is
        /// replaced the same way (audit B17): neither ends the endpoint.
        pub async fn serve<F, Fut, R>(&self, handler: F) -> Result<(), IpcError>
        where
            F: Fn(IpcRequest) -> Fut + Clone + Send + Sync + 'static,
            Fut: Future<Output = R> + Send + 'static,
            R: Into<Reply> + Send + 'static,
        {
            let Some(mut waiting) = self
                .waiting
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take()
            else {
                return Err(IpcError::Unsupported("the pipe is served once"));
            };
            let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
            loop {
                if let Err(e) = waiting.connect().await {
                    // A client that came and went before the connection
                    // completed: the instance is freed and waits again.
                    tracing::debug!(error = %e, "an IPC client left before it was served");
                    let _ = waiting.disconnect();
                    tokio::time::sleep(BUSY_WAIT).await;
                    continue;
                }
                let Ok(slot) = Arc::clone(&slots).try_acquire_owned() else {
                    tracing::warn!(
                        max = MAX_CONNECTIONS,
                        "IPC endpoint at its connection limit; refused one"
                    );
                    if let Err(e) = waiting.disconnect() {
                        // Made before the old one is dropped: the name stays.
                        tracing::warn!(error = %e, "an IPC pipe instance could not be freed");
                        waiting = self.next_instance().await;
                    }
                    continue;
                };
                let connected = std::mem::replace(&mut waiting, self.next_instance().await);
                let handler = handler.clone();
                let account = self.account.clone();
                tokio::spawn(async move {
                    let _slot = slot;
                    if let Err(e) = serve_one(connected, &account, &handler).await {
                        // One bad client must never take the endpoint down.
                        tracing::warn!(error = %e, "IPC connection dropped");
                    }
                });
            }
        }
    }

    impl Endpoint {
        /// A new waiting instance, tried until it is made; the caller holds
        /// an instance meanwhile, so the name never lapses.
        async fn next_instance(&self) -> NamedPipeServer {
            until_made("making the IPC pipe's next instance", || {
                instance(&self.name, &self.descriptor, false)
            })
            .await
        }
    }

    async fn serve_one<F, Fut, R>(
        mut pipe: NamedPipeServer,
        account: &str,
        handler: &F,
    ) -> Result<(), IpcError>
    where
        F: Fn(IpcRequest) -> Fut,
        Fut: Future<Output = R>,
        R: Into<Reply>,
    {
        // §B.8.7.4: the client's account is checked before any frame is read.
        let pid = client_pid(&pipe)?;
        check_account(account_of(pid), account, pid)?;
        serve_frames(&mut pipe, handler).await
    }

    /// Open the pipe whose name the host wrote into `state_dir`'s name file,
    /// waiting while every instance is busy (up to [`IDLE_TIMEOUT`]); the
    /// server is identified, never allowed to impersonate this process. No
    /// name file, or no pipe of that name, means no host; a name file that
    /// holds anything else is refused before any pipe is opened.
    async fn open(state_dir: &Path, wait: bool) -> Result<NamedPipeClient, IpcError> {
        let name = read_pipe_name(state_dir)?;
        let until = Instant::now() + IDLE_TIMEOUT;
        loop {
            let opened = ClientOptions::new()
                .security_qos_flags(SECURITY_IDENTIFICATION)
                .open(&name);
            match opened {
                Ok(pipe) => return Ok(pipe),
                Err(e) if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32) => {
                    return Err(IpcError::NotRunning(state_dir.to_path_buf()));
                }
                Err(e)
                    if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32)
                        && wait
                        && Instant::now() < until =>
                {
                    tokio::time::sleep(BUSY_WAIT).await;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Send one request to a running host and read its answer: the server's
    /// account is checked first, before anything is sent (§B.8.7.4).
    pub async fn request(state_dir: &Path, req: &IpcRequest) -> Result<IpcResponse, IpcError> {
        let mut pipe = open(state_dir, true).await?;
        let pid = server_pid(&pipe)?;
        check_account(account_of(pid), &current_user_sid()?, pid)?;
        exchange(&mut pipe, req).await
    }

    /// Whether a host of this account is serving this state directory right
    /// now (a busy pipe is one): a pipe whose server runs as another account,
    /// or whose account cannot be read, is none (§B.8.7.4).
    pub async fn is_running(state_dir: &Path) -> bool {
        running(open(state_dir, false).await, |pipe| {
            let pid = server_pid(pipe)?;
            check_account(account_of(pid), &current_user_sid()?, pid)
        })
    }
}

pub use imp::{Endpoint, is_running, request};

/// The Windows pipe's rules that do not need Windows (§B.8.7.4); the calls
/// themselves are type-checked here and NEEDS-DEVICE(windows).
#[cfg(test)]
mod pipe_rules {
    use super::*;

    /// Audit B17: the pause after each failure the endpoint outlives: 50 ms,
    /// doubling to at most 1 s, and 50 ms again after an accepted connection.
    #[test]
    fn a_failure_the_endpoint_outlives_pauses_it_briefly() {
        let mut backoff = Backoff::new();
        let pauses: Vec<Duration> = (0..7).map(|_| backoff.failed()).collect();
        assert_eq!(
            pauses,
            [50, 100, 200, 400, 800, 1000, 1000].map(Duration::from_millis)
        );
        backoff.succeeded();
        assert_eq!(backoff.failed(), Duration::from_millis(50));
    }

    /// Audit B17 (Windows): a next pipe instance that cannot be made yet
    /// (every instance taken, `ERROR_PIPE_BUSY`, while a finished
    /// connection's handle is still closing; `ERROR_NO_SYSTEM_RESOURCES`) is
    /// tried again after a pause until it is made. It used to end the
    /// endpoint, and the control channel was gone until the host restarted.
    #[tokio::test(start_paused = true)]
    async fn a_pipe_instance_that_cannot_be_made_yet_is_tried_again() {
        const NO_SYSTEM_RESOURCES: i32 = 1450;
        let started = tokio::time::Instant::now();
        let mut failures = vec![
            std::io::Error::from_raw_os_error(NO_SYSTEM_RESOURCES),
            std::io::Error::from_raw_os_error(PIPE_FULL),
            std::io::Error::from_raw_os_error(PIPE_FULL),
        ];
        let mut tries = 0;
        let made = until_made("making the next instance", || {
            tries += 1;
            failures.pop().map_or(Ok("the instance"), Err)
        })
        .await;
        assert_eq!(made, "the instance");
        assert_eq!(tries, 4);
        assert_eq!(started.elapsed(), Duration::from_millis(50 + 100 + 200));
    }

    /// A second server, finding the pipe made already (`FILE_FLAG_FIRST_PIPE_INSTANCE`
    /// fails, or every instance is taken), gets no endpoint and so serves nothing;
    /// it never uses the pipe that exists. Any other failure is reported as is.
    #[test]
    fn a_second_server_instance_fails_to_create_and_serves_nothing() {
        for code in [PIPE_EXISTS, PIPE_FULL] {
            let taken = claim_first::<()>(Err(std::io::Error::from_raw_os_error(code)));
            assert!(
                matches!(taken, Err(IpcError::NameTaken)),
                "{code}: {taken:?}"
            );
        }
        let other = claim_first::<()>(Err(std::io::Error::from_raw_os_error(2)));
        assert!(matches!(other, Err(IpcError::Io(_))), "{other:?}");
        assert!(matches!(claim_first(Ok(7)), Ok(7)));
    }

    /// Each end refuses a peer of another account, and one whose account could
    /// not be read, before a frame is read or sent; the client refuses a server
    /// whose SID differs.
    #[test]
    fn the_client_refuses_a_server_whose_sid_differs() {
        let own = "S-1-5-21-1000-2000-3000-1001";
        assert!(check_account(Ok(own.to_owned()), own, 42).is_ok());
        let other = check_account(Ok("S-1-5-21-1000-2000-3000-1002".to_owned()), own, 42);
        assert!(
            matches!(other, Err(IpcError::ForeignAccount { pid: 42 })),
            "{other:?}"
        );
        let unreadable = check_account(Err(std::io::Error::from_raw_os_error(5)), own, 43);
        assert!(
            matches!(unreadable, Err(IpcError::ForeignAccount { pid: 43 })),
            "{unreadable:?}"
        );
    }

    /// A name file left by a host that did not stop cleanly is trusted only for a pipe of
    /// this account: a pipe the command line opened is a running host only when its
    /// server's account is this account; another account's pipe, one whose account cannot
    /// be read and one whose server's process cannot be told are not, so the command line
    /// falls to the host lock (the offline guard when no host holds it). A pipe whose every
    /// instance is busy still counts; no name file, no pipe and a name file that is not one
    /// are no host.
    #[test]
    fn a_pipe_of_another_account_is_no_running_host() {
        let own = "S-1-5-21-1000-2000-3000-1001";
        let opened = || Ok::<(), IpcError>(());
        assert!(running(opened(), |_| check_account(
            Ok(own.to_owned()),
            own,
            42
        )));
        assert!(!running(opened(), |_| check_account(
            Ok("S-1-5-21-1000-2000-3000-1002".to_owned()),
            own,
            42
        )));
        assert!(!running(opened(), |_| check_account(
            Err(std::io::Error::from_raw_os_error(5)),
            own,
            43
        )));
        assert!(!running(opened(), |_| Err(IpcError::Io(
            std::io::Error::from_raw_os_error(1)
        ))));
        let not_asked = |_: &()| -> Result<(), IpcError> { panic!("no pipe was opened") };
        let busy = IpcError::Io(std::io::Error::from_raw_os_error(PIPE_FULL));
        assert!(running(Err(busy), not_asked));
        for none in [
            IpcError::NotRunning(PathBuf::from("state")),
            IpcError::NameFile,
            IpcError::Io(std::io::Error::from_raw_os_error(2)),
        ] {
            assert!(!running(Err(none), not_asked));
        }
    }

    /// The name: `\\.\pipe\tornect-ctl-` and the 32 lowercase hex digits of 16
    /// random bytes, another at each start, never the helper's prefix and
    /// never anything computed from the state directory.
    #[test]
    fn a_control_pipe_name_is_random_each_time() {
        let fixed = control_pipe_name(&[0xab; 16]);
        assert_eq!(fixed, format!(r"\\.\pipe\tornect-ctl-{}", "ab".repeat(16)));
        assert!(valid_control_pipe_name(&fixed));
        let first = new_control_pipe_name().unwrap();
        let second = new_control_pipe_name().unwrap();
        assert_ne!(first, second);
        for name in [&first, &second] {
            assert!(valid_control_pipe_name(name), "{name}");
            assert!(!name.starts_with(crate::helper::PIPE_PREFIX), "{name}");
        }
        assert_eq!(first.len(), CONTROL_PIPE_PREFIX.len() + 32);
    }

    fn write_here(dir: &Path, name: &str) -> std::io::Result<()> {
        write_pipe_name(
            dir,
            name,
            |tmp| std::fs::File::create_new(tmp),
            |from, to| std::fs::rename(from, to),
        )
    }

    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /// What the host writes the command line reads back, with no temporary
    /// file left; a later start replaces the name; a stopping host removes
    /// only its own name; a failed write leaves the name file as it was.
    #[test]
    fn the_name_file_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let first = new_control_pipe_name().unwrap();
        write_here(dir, &first).unwrap();
        assert_eq!(read_pipe_name(dir).unwrap(), first);
        assert_eq!(
            std::fs::read(dir.join(PIPE_NAME_FILE)).unwrap(),
            first.as_bytes()
        );
        assert_eq!(entries(dir), [PIPE_NAME_FILE]);

        let second = new_control_pipe_name().unwrap();
        write_here(dir, &second).unwrap();
        assert_eq!(read_pipe_name(dir).unwrap(), second);
        assert_eq!(entries(dir), [PIPE_NAME_FILE]);

        let failed = write_pipe_name(
            dir,
            &first,
            |tmp| std::fs::File::create_new(tmp),
            |_, _| Err(std::io::Error::other("the move failed")),
        );
        assert!(failed.is_err());
        assert_eq!(read_pipe_name(dir).unwrap(), second);
        assert_eq!(entries(dir), [PIPE_NAME_FILE]);

        remove_pipe_name(dir, &first);
        assert_eq!(read_pipe_name(dir).unwrap(), second);
        remove_pipe_name(dir, &second);
        assert!(entries(dir).is_empty());
    }

    /// The Windows bind (§B.8.7.4): a fresh name at each bind, the pipe's first
    /// instance created under it before the name file is written; a pipe that
    /// already exists (5, or 231 with every instance taken) is refused with no
    /// file written, moved or removed; a name file that could not be written
    /// means no channel and no `ipc.pipe`, an earlier one removed too. The
    /// descriptor is NEEDS-DEVICE(windows).
    #[test]
    fn bind_creates_the_pipe_under_a_fresh_name_before_its_name_file() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        let order = std::cell::RefCell::new(Vec::new());
        let bind = || {
            bind_steps(
                dir,
                || {
                    order.borrow_mut().push("name");
                    new_control_pipe_name()
                },
                |name| {
                    order.borrow_mut().push("pipe");
                    Ok(name.to_owned())
                },
                |tmp| {
                    order.borrow_mut().push("file");
                    std::fs::File::create_new(tmp)
                },
                |from, to| {
                    order.borrow_mut().push("move");
                    std::fs::rename(from, to)
                },
            )
        };
        let (first, pipe) = bind().unwrap();
        assert_eq!(pipe, first, "the pipe carries the name drawn");
        assert_eq!(*order.borrow(), ["name", "pipe", "file", "move"]);
        assert_eq!(read_pipe_name(dir).unwrap(), first);
        let (second, _) = bind().unwrap();
        assert_ne!(first, second, "a fresh name at each bind");
        assert_eq!(read_pipe_name(dir).unwrap(), second);
        for code in [PIPE_EXISTS, PIPE_FULL] {
            let taken = bind_steps(
                dir,
                new_control_pipe_name,
                |_| Err::<(), _>(std::io::Error::from_raw_os_error(code)),
                |_| -> std::io::Result<std::fs::File> { panic!("{code}: a file was written") },
                |_, _| -> std::io::Result<()> { panic!("{code}: a file was moved") },
            );
            assert!(
                matches!(taken, Err(IpcError::NameTaken)),
                "{code}: {taken:?}"
            );
            assert_eq!(read_pipe_name(dir).unwrap(), second, "{code}");
            assert_eq!(entries(dir), [PIPE_NAME_FILE], "{code}");
        }
        let failed = bind_steps(
            dir,
            new_control_pipe_name,
            |name| Ok(name.to_owned()),
            |tmp| std::fs::File::create_new(tmp),
            |_, _| Err(std::io::Error::other("the move failed")),
        );
        assert!(matches!(failed, Err(IpcError::Io(_))), "{failed:?}");
        assert!(entries(dir).is_empty(), "{:?}", entries(dir));
    }

    /// No name file is no host: the command line opens no pipe and computes
    /// no name.
    #[test]
    fn no_name_file_means_no_host() {
        let tmp = tempfile::tempdir().unwrap();
        let read = read_pipe_name(tmp.path());
        assert!(
            matches!(&read, Err(IpcError::NotRunning(dir)) if dir == tmp.path()),
            "{read:?}"
        );
    }

    /// A name file that holds anything but exactly a control pipe's name is
    /// refused, never taken for a running host: the helper's pipe, another
    /// machine's pipe, extra bytes, upper case, a short name, an empty file,
    /// bytes that are not text, an overlong file.
    #[test]
    fn a_name_file_that_is_not_a_control_pipe_is_refused() {
        let hex = "0123456789abcdef".repeat(2);
        let good = format!(r"\\.\pipe\tornect-ctl-{hex}");
        let bad: Vec<Vec<u8>> = vec![
            crate::helper::pipe_name(&[7; 16]).into_bytes(),
            format!(r"\\server\pipe\tornect-ctl-{hex}").into_bytes(),
            format!("{good}\n").into_bytes(),
            format!(" {good}").into_bytes(),
            format!("{good}00").into_bytes(),
            good.to_uppercase().into_bytes(),
            format!(r"\\.\pipe\tornect-ctl-{}", hex.to_uppercase()).into_bytes(),
            good.as_bytes()[..good.len() - 1].to_vec(),
            Vec::new(),
            vec![0xff; 53],
            good.repeat(3).into_bytes(),
        ];
        for bytes in bad {
            let tmp = tempfile::tempdir().unwrap();
            std::fs::write(tmp.path().join(PIPE_NAME_FILE), &bytes).unwrap();
            let read = read_pipe_name(tmp.path());
            assert!(
                matches!(read, Err(IpcError::NameFile)),
                "{:?}: {read:?}",
                String::from_utf8_lossy(&bytes)
            );
        }
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join(PIPE_NAME_FILE), &good).unwrap();
        assert_eq!(read_pipe_name(tmp.path()).unwrap(), good);
        assert_eq!(
            IpcError::NameFile.to_string(),
            "the control channel's name file is not one Tornect wrote; no host was asked"
        );
    }
}

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

    /// A listener whose next accepts fail with `errors` (the last one first),
    /// then the real one's.
    struct Flaky {
        inner: tokio::net::UnixListener,
        errors: std::sync::Mutex<Vec<std::io::Error>>,
    }

    impl imp::Accept for Flaky {
        fn next_connection(
            &self,
        ) -> impl Future<Output = std::io::Result<tokio::net::UnixStream>> + Send {
            let failure = self.errors.lock().unwrap().pop();
            async move {
                match failure {
                    Some(e) => Err(e),
                    None => self.inner.accept().await.map(|(stream, _)| stream),
                }
            }
        }
    }

    /// A [`Flaky`] listener bound at `dir`'s socket, and the uid owning it.
    fn flaky(dir: &Path, errors: Vec<std::io::Error>) -> (Flaky, u32) {
        use std::os::unix::fs::MetadataExt as _;
        let path = socket_path(dir);
        let inner = tokio::net::UnixListener::bind(&path).unwrap();
        let owner = fs_err::metadata(&path).unwrap().uid();
        let errors = std::sync::Mutex::new(errors);
        (Flaky { inner, errors }, owner)
    }

    /// Audit B17: an `accept` that fails (the descriptor limit, `EMFILE` or
    /// `ENFILE`; a connection aborted before it was taken; an interrupted
    /// call) pauses the endpoint, which then answers as before. It used to
    /// end it: `tornect panic`, the second launch's Show and every `tornect
    /// unattended` command failed until the host restarted.
    #[tokio::test]
    async fn an_accept_that_fails_does_not_end_the_endpoint() {
        const ENFILE: i32 = 23;
        const EMFILE: i32 = 24;
        let tmp = tempfile::tempdir().unwrap();
        let dir = state_dir(&tmp);
        let (listener, owner) = flaky(
            &dir,
            vec![
                std::io::Error::from(ErrorKind::Interrupted),
                std::io::Error::from(ErrorKind::ConnectionAborted),
                std::io::Error::from_raw_os_error(ENFILE),
                std::io::Error::from_raw_os_error(EMFILE),
            ],
        );
        let server = tokio::spawn(async move {
            imp::accept_loop(&listener, owner, |req: IpcRequest| async move {
                IpcResponse::ok(req.id)
            })
            .await
        });
        for id in [1, 2] {
            let resp = tokio::time::timeout(
                Duration::from_secs(10),
                request(
                    &dir,
                    &IpcRequest {
                        id,
                        op: IpcOp::Status,
                    },
                ),
            )
            .await
            .expect("the endpoint answers after the failures")
            .unwrap();
            assert!(resp.ok);
            assert_eq!(resp.id, id);
        }
        assert!(!server.is_finished(), "the endpoint ended");
        server.abort();
    }

    /// Only a listening socket that is itself unusable ends the endpoint,
    /// with its error.
    #[tokio::test]
    async fn an_unusable_listener_ends_the_endpoint() {
        const EBADF: i32 = 9;
        let tmp = tempfile::tempdir().unwrap();
        let dir = state_dir(&tmp);
        let (listener, owner) = flaky(&dir, vec![std::io::Error::from_raw_os_error(EBADF)]);
        let ended = tokio::time::timeout(
            Duration::from_secs(10),
            imp::accept_loop(&listener, owner, |req: IpcRequest| async move {
                IpcResponse::ok(req.id)
            }),
        )
        .await
        .expect("an unusable listener ends the loop");
        match ended {
            Err(IpcError::Io(e)) => assert_eq!(e.raw_os_error(), Some(EBADF)),
            other => panic!("{other:?}"),
        }
    }

    /// Which `accept` errors end the endpoint (the listening socket is
    /// unusable) and which it outlives.
    #[test]
    fn only_an_unusable_listener_ends_the_endpoint() {
        let errno = std::io::Error::from_raw_os_error;
        for gone in [9, 22] {
            assert!(listener_is_gone(&errno(gone)), "{gone}");
        }
        for passing in [1, 4, 12, 23, 24] {
            assert!(!listener_is_gone(&errno(passing)), "{passing}");
        }
        assert!(!listener_is_gone(&std::io::Error::from(
            ErrorKind::ConnectionAborted
        )));
        #[cfg(target_os = "linux")]
        {
            // ENOTSOCK; ENOBUFS, ECONNABORTED, EPROTO.
            assert!(listener_is_gone(&errno(88)));
            for passing in [105, 103, 71] {
                assert!(!listener_is_gone(&errno(passing)), "{passing}");
            }
        }
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
