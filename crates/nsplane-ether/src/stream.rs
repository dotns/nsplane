//! Framed byte-stream transport: every frame is a 4-byte big-endian length followed by
//! the frame bytes.
//!
//! This is the convention of passt and of QEMU's `-netdev stream`, also used by libkrun in
//! its passt mode. A zero length or a length above [`MAX_FRAME_LEN`] is a protocol error
//! that ends the transport.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::transport::{FrameRead, FrameWrite, MAX_FRAME_LEN};

/// Length of the frame length prefix.
const PREFIX_LEN: usize = 4;

/// Reads length-prefixed frames from a byte stream.
#[derive(Debug)]
pub struct FramedReader<R> {
    inner: R,
}

impl<R> FramedReader<R> {
    /// Reads frames from `inner`.
    pub const fn new(inner: R) -> Self {
        Self { inner }
    }

    /// The underlying stream.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: AsyncRead + Unpin + Send + 'static> FrameRead for FramedReader<R> {
    /// Reads one frame. End of stream before the first prefix byte is the clean end; end of
    /// stream inside a prefix or a frame is [`io::ErrorKind::UnexpectedEof`], and a zero or
    /// oversized length is [`io::ErrorKind::InvalidData`].
    async fn read_frame(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        let mut prefix = [0; PREFIX_LEN];
        let mut filled = 0;
        while filled < PREFIX_LEN {
            match self.inner.read(&mut prefix[filled..]).await? {
                0 if filled == 0 => return Ok(None),
                0 => return Err(io::ErrorKind::UnexpectedEof.into()),
                n => filled += n,
            }
        }
        let len = usize::try_from(u32::from_be_bytes(prefix)).unwrap_or(usize::MAX);
        if len == 0 || len > MAX_FRAME_LEN || len > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid frame length {len}"),
            ));
        }
        self.inner.read_exact(&mut buf[..len]).await?;
        Ok(Some(len))
    }
}

/// Writes length-prefixed frames to a byte stream.
#[derive(Debug)]
pub struct FramedWriter<W> {
    inner: W,
    scratch: Vec<u8>,
}

impl<W> FramedWriter<W> {
    /// Writes frames to `inner`.
    pub const fn new(inner: W) -> Self {
        Self {
            inner,
            scratch: Vec::new(),
        }
    }

    /// The underlying stream.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: AsyncWrite + Unpin + Send + 'static> FrameWrite for FramedWriter<W> {
    /// Writes the prefix and the frame in one write and flushes. A zero-length or
    /// oversized frame is [`io::ErrorKind::InvalidInput`] and nothing is written.
    async fn write_frame(&mut self, frame: &[u8]) -> io::Result<()> {
        let len = u32::try_from(frame.len())
            .ok()
            .filter(|_| (1..=MAX_FRAME_LEN).contains(&frame.len()))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid frame length {}", frame.len()),
                )
            })?;
        self.scratch.clear();
        self.scratch.extend_from_slice(&len.to_be_bytes());
        self.scratch.extend_from_slice(frame);
        self.inner.write_all(&self.scratch).await?;
        self.inner.flush().await
    }
}

/// Splits the connected Unix stream `stream` into a frame reader and writer.
#[cfg(unix)]
pub fn unix(
    stream: tokio::net::UnixStream,
) -> (
    FramedReader<tokio::net::unix::OwnedReadHalf>,
    FramedWriter<tokio::net::unix::OwnedWriteHalf>,
) {
    let (read, write) = stream.into_split();
    (FramedReader::new(read), FramedWriter::new(write))
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::ReadBuf;

    use super::*;

    /// Yields its bytes at most `chunk` at a time.
    struct Chunked {
        bytes: Vec<u8>,
        pos: usize,
        chunk: usize,
    }

    impl AsyncRead for Chunked {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let end = self.bytes.len().min(self.pos.saturating_add(self.chunk));
            let n = (end - self.pos).min(buf.remaining());
            buf.put_slice(&self.bytes[self.pos..self.pos + n]);
            self.pos += n;
            Poll::Ready(Ok(()))
        }
    }

    /// Yields all of `bytes` in one read.
    fn whole(bytes: &[u8]) -> Chunked {
        Chunked {
            bytes: bytes.to_vec(),
            pos: 0,
            chunk: usize::MAX,
        }
    }

    async fn encode(frames: &[&[u8]]) -> Vec<u8> {
        let mut writer = FramedWriter::new(Vec::new());
        for frame in frames {
            writer.write_frame(frame).await.unwrap();
        }
        writer.into_inner()
    }

    async fn read_all<R: AsyncRead + Unpin + Send + 'static>(
        reader: R,
    ) -> io::Result<Vec<Vec<u8>>> {
        let mut reader = FramedReader::new(reader);
        let mut buf = vec![0; MAX_FRAME_LEN];
        let mut frames = Vec::new();
        while let Some(len) = reader.read_frame(&mut buf).await? {
            frames.push(buf[..len].to_vec());
        }
        Ok(frames)
    }

    #[tokio::test]
    async fn round_trip() {
        let big = vec![0xab; MAX_FRAME_LEN];
        let bytes = encode(&[b"hello", &big]).await;
        assert_eq!(bytes[..9], [0, 0, 0, 5, b'h', b'e', b'l', b'l', b'o']);
        assert_eq!(bytes.len(), 4 + 5 + 4 + MAX_FRAME_LEN);
        let frames = read_all(whole(&bytes[..])).await.unwrap();
        assert_eq!(frames, vec![b"hello".to_vec(), big]);
    }

    #[tokio::test]
    async fn frame_split_across_partial_reads() {
        let bytes = encode(&[b"split into single bytes", b"x"]).await;
        let reader = Chunked {
            bytes,
            pos: 0,
            chunk: 1,
        };
        let frames = read_all(reader).await.unwrap();
        assert_eq!(
            frames,
            vec![b"split into single bytes".to_vec(), b"x".to_vec()]
        );
    }

    #[tokio::test]
    async fn two_frames_in_one_read() {
        let bytes = encode(&[b"one", b"two"]).await;
        let frames = read_all(whole(&bytes)).await.unwrap();
        assert_eq!(frames, vec![b"one".to_vec(), b"two".to_vec()]);
    }

    #[tokio::test]
    async fn bad_lengths_rejected() {
        let too_long = u32::try_from(MAX_FRAME_LEN + 1).unwrap().to_be_bytes();
        let err = read_all(whole(&too_long[..])).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let err = read_all(whole(&[0, 0, 0, 0])).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        let mut writer = FramedWriter::new(Vec::new());
        let err = writer.write_frame(&[]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let err = writer
            .write_frame(&vec![0; MAX_FRAME_LEN + 1])
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(writer.into_inner().len(), 0);
    }

    #[tokio::test]
    async fn eof_mid_frame_is_an_error() {
        let bytes = encode(&[b"truncated"]).await;
        for cut in [2, 4, 8] {
            let err = read_all(whole(&bytes[..cut])).await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof, "cut at {cut}");
        }
    }

    #[tokio::test]
    async fn eof_between_frames_ends_the_stream() {
        assert_eq!(read_all(whole(&[])).await.unwrap().len(), 0);
        let bytes = encode(&[b"a", b"b"]).await;
        assert_eq!(read_all(whole(&bytes[..])).await.unwrap().len(), 2);
    }
}
