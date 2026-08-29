//! Length-prefixed frames (`docs/PLAN.md` §B.3): a `u32` big-endian length
//! followed by that many payload bytes, at most [`MAX_FRAME_LEN`] per frame.
//!
//! Shared by the interim ping protocol and the CBOR envelope protocol. Works over
//! any tokio `AsyncRead`/`AsyncWrite`; every write ends with `flush()` because
//! Arti's `DataStream` buffers (docs/research/arti.md §8.3).

use std::io::ErrorKind;

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

/// Largest payload accepted or produced (64 KiB).
pub const MAX_FRAME_LEN: usize = 65_536;

/// Size of the length prefix in bytes.
pub const HEADER_LEN: usize = 4;

/// Framing failures.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FrameError {
    /// A frame longer than the limit in force ([`MAX_FRAME_LEN`], or the
    /// smaller cap a protocol passed to [`read_frame_max`]) was announced or
    /// requested.
    #[error("frame of {len} bytes exceeds the {max}-byte limit")]
    TooLarge {
        /// Announced or requested payload length.
        len: usize,
        /// The limit that was exceeded.
        max: usize,
    },
    /// The stream ended in the middle of a frame.
    #[error("stream ended in the middle of a frame")]
    Truncated,
    /// Underlying transport error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Read one frame of up to [`MAX_FRAME_LEN`] bytes.
///
/// Returns `Ok(None)` when the peer closed the stream cleanly at a frame boundary;
/// an EOF anywhere inside a frame is [`FrameError::Truncated`]. An oversize
/// length prefix is rejected before any payload is read.
pub async fn read_frame<R>(reader: &mut R) -> Result<Option<Vec<u8>>, FrameError>
where
    R: AsyncRead + Unpin,
{
    read_frame_max(reader, MAX_FRAME_LEN).await
}

/// [`read_frame`] with a tighter cap: a length prefix above `max_len` (clamped
/// to [`MAX_FRAME_LEN`]) is rejected before the payload buffer is allocated.
///
/// Protocols whose messages have a known size pass it here, so an
/// unauthenticated peer cannot make the host reserve 64 KiB per stream by
/// announcing a large frame it never sends.
pub async fn read_frame_max<R>(
    reader: &mut R,
    max_len: usize,
) -> Result<Option<Vec<u8>>, FrameError>
where
    R: AsyncRead + Unpin,
{
    let max = max_len.min(MAX_FRAME_LEN);
    let mut header = [0u8; HEADER_LEN];
    let mut filled = 0;
    while filled < HEADER_LEN {
        let n = reader.read(&mut header[filled..]).await?;
        if n == 0 {
            return if filled == 0 {
                Ok(None)
            } else {
                Err(FrameError::Truncated)
            };
        }
        filled += n;
    }
    let len = u32::from_be_bytes(header) as usize;
    if len > max {
        return Err(FrameError::TooLarge { len, max });
    }
    let mut payload = vec![0u8; len];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|e| match e.kind() {
            ErrorKind::UnexpectedEof => FrameError::Truncated,
            _ => FrameError::Io(e),
        })?;
    Ok(Some(payload))
}

/// Write one frame (header + payload in a single write) and flush.
pub async fn write_frame<W>(writer: &mut W, payload: &[u8]) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
{
    let len = u32::try_from(payload.len())
        .ok()
        .filter(|_| payload.len() <= MAX_FRAME_LEN)
        .ok_or(FrameError::TooLarge {
            len: payload.len(),
            max: MAX_FRAME_LEN,
        })?;
    let mut buf = Vec::with_capacity(HEADER_LEN + payload.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(payload);
    writer.write_all(&buf).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn roundtrip_various_sizes() {
        for payload in [
            Vec::new(),
            b"hello".to_vec(),
            vec![0xAB; 1000],
            vec![0x5C; MAX_FRAME_LEN],
        ] {
            let (mut a, mut b) = duplex(4096);
            let writer = async { write_frame(&mut a, &payload).await };
            let reader = async { read_frame(&mut b).await };
            let (w, r) = tokio::join!(writer, reader);
            w.unwrap();
            assert_eq!(r.unwrap().unwrap(), payload);
        }
    }

    #[tokio::test]
    async fn several_frames_then_clean_eof() {
        let (mut a, mut b) = duplex(64);
        let writer = async {
            write_frame(&mut a, b"one").await.unwrap();
            write_frame(&mut a, b"").await.unwrap();
            write_frame(&mut a, b"three").await.unwrap();
            drop(a);
        };
        let reader = async {
            assert_eq!(read_frame(&mut b).await.unwrap().unwrap(), b"one");
            assert_eq!(read_frame(&mut b).await.unwrap().unwrap(), b"");
            assert_eq!(read_frame(&mut b).await.unwrap().unwrap(), b"three");
            assert!(read_frame(&mut b).await.unwrap().is_none());
        };
        tokio::join!(writer, reader);
    }

    #[tokio::test]
    async fn oversize_payload_rejected_on_write() {
        let (mut a, _b) = duplex(16);
        let err = write_frame(&mut a, &vec![0u8; MAX_FRAME_LEN + 1])
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            FrameError::TooLarge { len, max } if len == MAX_FRAME_LEN + 1 && max == MAX_FRAME_LEN
        ));
    }

    #[tokio::test]
    async fn oversize_header_rejected_before_reading_body() {
        let (mut a, mut b) = duplex(16);
        let len = (MAX_FRAME_LEN as u32) + 1;
        a.write_all(&len.to_be_bytes()).await.unwrap();
        let err = read_frame(&mut b).await.unwrap_err();
        assert!(matches!(
            err,
            FrameError::TooLarge { len, max } if len == MAX_FRAME_LEN + 1 && max == MAX_FRAME_LEN
        ));
    }

    #[tokio::test]
    async fn protocol_cap_rejects_the_header_without_touching_the_body() {
        // The peer announces 1000 bytes and sends them; a 22-byte protocol must
        // refuse at the header and leave the body unread (nothing was allocated
        // for it, and the caller decides what happens to the stream).
        let (mut a, mut b) = duplex(4096);
        let mut frame = 1000u32.to_be_bytes().to_vec();
        frame.extend_from_slice(&[7u8; 1000]);
        a.write_all(&frame).await.unwrap();
        let err = read_frame_max(&mut b, 22).await.unwrap_err();
        assert!(
            matches!(err, FrameError::TooLarge { len: 1000, max: 22 }),
            "{err}"
        );
        let mut rest = vec![0u8; 1000];
        b.read_exact(&mut rest).await.unwrap();
        assert!(rest.iter().all(|&byte| byte == 7), "body left unread");

        // Within the cap, it is an ordinary read; the cap never exceeds the wire limit.
        let (mut a, mut b) = duplex(64);
        write_frame(&mut a, &[1u8; 22]).await.unwrap();
        assert_eq!(
            read_frame_max(&mut b, 22).await.unwrap().unwrap(),
            [1u8; 22]
        );
        let (mut a, mut b) = duplex(16);
        a.write_all(&((MAX_FRAME_LEN as u32) + 1).to_be_bytes())
            .await
            .unwrap();
        let err = read_frame_max(&mut b, usize::MAX).await.unwrap_err();
        assert!(matches!(err, FrameError::TooLarge { max, .. } if max == MAX_FRAME_LEN));
    }

    #[tokio::test]
    async fn truncated_body_is_an_error() {
        let (mut a, mut b) = duplex(64);
        a.write_all(&10u32.to_be_bytes()).await.unwrap();
        a.write_all(b"four").await.unwrap();
        drop(a);
        assert!(matches!(
            read_frame(&mut b).await.unwrap_err(),
            FrameError::Truncated
        ));
    }

    #[tokio::test]
    async fn truncated_header_is_an_error() {
        let (mut a, mut b) = duplex(64);
        a.write_all(&[0, 0]).await.unwrap();
        drop(a);
        assert!(matches!(
            read_frame(&mut b).await.unwrap_err(),
            FrameError::Truncated
        ));
    }

    proptest! {
        #[test]
        fn any_payload_roundtrips_through_a_tiny_pipe(payload in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
            rt.block_on(async {
                // A 7-byte pipe forces partial reads of both header and body.
                let (mut a, mut b) = duplex(7);
                let writer = async { write_frame(&mut a, &payload).await };
                let reader = async { read_frame(&mut b).await };
                let (w, r) = tokio::join!(writer, reader);
                w.unwrap();
                prop_assert_eq!(r.unwrap().unwrap(), payload);
                Ok(())
            })?;
        }
    }
}
