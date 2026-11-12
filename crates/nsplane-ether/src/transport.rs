//! Frame transports: where the guest's ethernet frames come from and go to.

use std::io;

/// Largest frame a transport carries: a 64 KiB IP packet behind an ethernet header.
pub const MAX_FRAME_LEN: usize = 65535 + crate::frame::HEADER_LEN;

/// Reads whole ethernet frames from the guest.
pub trait FrameRead: Send + 'static {
    /// Reads the next frame into the front of `buf` and returns its length, or `None` at
    /// the clean end of the transport.
    ///
    /// `buf` holds at least [`MAX_FRAME_LEN`] bytes. An error ends the transport and the
    /// caller does not read again, unless [`is_transient`](Self::is_transient) says the
    /// error is transient. The future is not cancellation safe: dropping it may lose part
    /// of a frame.
    fn read_frame(
        &mut self,
        buf: &mut [u8],
    ) -> impl Future<Output = io::Result<Option<usize>>> + Send;

    /// Whether `err`, returned by [`read_frame`](Self::read_frame), is transient: the
    /// transport is intact and a later read can succeed (an interrupted call, a link that
    /// has gone down).
    ///
    /// The default is `false`: every error is fatal. That is the only right answer for a
    /// transport that cannot find the next frame boundary after a failed read, such as a
    /// byte stream.
    fn is_transient(&self, err: &io::Error) -> bool {
        let _ = err;
        false
    }
}

/// Writes whole ethernet frames to the guest.
pub trait FrameWrite: Send + 'static {
    /// Writes the frame `frame`, waiting while the transport applies backpressure.
    ///
    /// An error ends the transport and the caller does not write again, unless
    /// [`is_transient`](Self::is_transient) says the error is transient. The future is not
    /// cancellation safe: dropping it may leave part of a frame written.
    fn write_frame(&mut self, frame: &[u8]) -> impl Future<Output = io::Result<()>> + Send;

    /// Whether `err`, returned by [`write_frame`](Self::write_frame), is transient: the
    /// frame was not written, the transport is intact and a later write can succeed.
    ///
    /// The default is `false`: every error is fatal. A transport that may have written
    /// part of a frame before the error, such as a byte stream, must keep it.
    fn is_transient(&self, err: &io::Error) -> bool {
        let _ = err;
        false
    }
}
