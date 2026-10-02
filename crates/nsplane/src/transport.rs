//! Network-side driver traits: how encrypted datagrams travel between peers.

use std::io;
use std::pin::Pin;

use nsplane_packet::{PacketBuf, Path, TransportId};

/// A datagram transport (a UDP socket, a relay, an in-memory link).
///
/// An engine runs any number of transports at once, each under its own [`Transport::id`];
/// a peer's [`Path::transport`] picks the transport its datagrams leave on.
pub trait Transport: Send + Sync + 'static {
    /// This transport's id, unique within an engine and reported in every received
    /// [`Path::transport`].
    fn id(&self) -> TransportId;

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
    /// arrived. A transport should not wait indefinitely here (drop instead), since its
    /// waiting datagrams hold back the engine's local packets. Once the transport is closed
    /// this returns [`io::ErrorKind::BrokenPipe`].
    fn send(&self, datagram: &[u8], to: &Path) -> impl Future<Output = io::Result<()>> + Send;
}

/// The boxed future a [`DynTransport`] method returns.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The object-safe form of [`Transport`], implemented for every transport.
///
/// [`Transport`] returns `impl Future`, so `dyn Transport` does not exist. Use
/// `Box<dyn DynTransport>` where transports of different types share one type: a list of
/// configured transports, a factory that picks UDP or a relay at runtime. A
/// `Box<dyn DynTransport>` is itself a [`Transport`] and can be handed to
/// [`EngineBuilder::transport`] or [`EngineHandle::add_transport`]; it allocates one future
/// per datagram, so pass concrete transports where their type is known.
///
/// [`EngineBuilder::transport`]: crate::EngineBuilder::transport
/// [`EngineHandle::add_transport`]: crate::EngineHandle::add_transport
pub trait DynTransport: Send + Sync + 'static {
    /// [`Transport::id`].
    fn id(&self) -> TransportId;

    /// [`Transport::recv`] with a boxed future.
    fn recv<'a>(&'a self, buf: &'a mut PacketBuf) -> BoxFuture<'a, io::Result<(usize, Path)>>;

    /// [`Transport::send`] with a boxed future.
    fn send<'a>(&'a self, datagram: &'a [u8], to: &'a Path) -> BoxFuture<'a, io::Result<()>>;
}

impl<T: Transport> DynTransport for T {
    fn id(&self) -> TransportId {
        Transport::id(self)
    }

    fn recv<'a>(&'a self, buf: &'a mut PacketBuf) -> BoxFuture<'a, io::Result<(usize, Path)>> {
        Box::pin(Transport::recv(self, buf))
    }

    fn send<'a>(&'a self, datagram: &'a [u8], to: &'a Path) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(Transport::send(self, datagram, to))
    }
}

impl Transport for Box<dyn DynTransport> {
    fn id(&self) -> TransportId {
        (**self).id()
    }

    async fn recv(&self, buf: &mut PacketBuf) -> io::Result<(usize, Path)> {
        (**self).recv(buf).await
    }

    async fn send(&self, datagram: &[u8], to: &Path) -> io::Result<()> {
        (**self).send(datagram, to).await
    }
}
