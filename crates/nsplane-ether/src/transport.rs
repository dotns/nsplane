//! Frame transports: where the guest's ethernet frames come from and go to.

use std::io;

/// Largest frame a transport carries: a 64 KiB IP packet behind an ethernet header.
pub const MAX_FRAME_LEN: usize = 65535 + crate::frame::HEADER_LEN;

/// Reads whole ethernet frames from the guest.
pub trait FrameRead: Send + 'static {
    /// Reads the next frame into the front of `buf` and returns its length, or `None` at
    /// the clean end of the transport.
    ///
    /// `buf` holds at least [`MAX_FRAME_LEN`] bytes. An error ends the transport; the
    /// caller does not read again. The future is not cancellation safe: dropping it may
    /// lose part of a frame.
    fn read_frame(
        &mut self,
        buf: &mut [u8],
    ) -> impl Future<Output = io::Result<Option<usize>>> + Send;
}

/// Writes whole ethernet frames to the guest.
pub trait FrameWrite: Send + 'static {
    /// Writes the frame `frame`, waiting while the transport applies backpressure.
    ///
    /// An error ends the transport; the caller does not write again. The future is not
    /// cancellation safe: dropping it may leave part of a frame written.
    fn write_frame(&mut self, frame: &[u8]) -> impl Future<Output = io::Result<()>> + Send;
}
