//! Network-side driver trait: how encrypted datagrams travel between peers.

use std::io;

use nsplane_packet::{PacketBuf, Path};

/// A datagram transport (a UDP socket, a relay, an in-memory link).
pub trait Transport: Send + Sync + 'static {
    /// Receives the next datagram into `buf`.
    ///
    /// Buffer contract: the transport grows `buf` to `buf.capacity()`, writes the
    /// datagram at the start of the packet region (`buf.as_packet_mut()`), then sets the
    /// packet length to the datagram length and returns `(len, path)`. The headroom is
    /// left untouched. A datagram longer than `buf.capacity()` is truncated to it (UDP
    /// semantics), so callers size the buffer for the largest expected datagram.
    ///
    /// `path.transport` is this transport's id, `path.addr` the sender's address, and
    /// `path.ecn` the ECN mark observed on the datagram ([`Ecn::NotEct`] when the
    /// platform does not report it).
    ///
    /// Once the transport is closed this returns [`io::ErrorKind::BrokenPipe`].
    ///
    /// [`Ecn::NotEct`]: nsplane_packet::Ecn::NotEct
    fn recv(&self, buf: &mut PacketBuf) -> impl Future<Output = io::Result<(usize, Path)>> + Send;

    /// Sends `datagram` to `to.addr`, marked with `to.ecn` where the transport can set it.
    ///
    /// Delivery is best effort: success means the datagram was handed off, not that it
    /// arrived. Once the transport is closed this returns [`io::ErrorKind::BrokenPipe`].
    fn send(&self, datagram: &[u8], to: &Path) -> impl Future<Output = io::Result<()>> + Send;
}
