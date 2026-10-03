//! Network-side driver traits: how encrypted datagrams travel between peers.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;

use nsplane_packet::{MAX_BATCH, PacketBuf, Path, TransportId};

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

    /// Receives the next datagrams and appends them to the back of `datagrams`, each with its
    /// [`Path`] as reported by [`recv`], in arrival order.
    ///
    /// Each datagram is an exactly sized [`PacketBuf`] the caller owns afterwards: a copy
    /// out of `buf`, or a buffer the transport produced itself (one slice of a coalesced
    /// read, say). `buf` is the caller's reusable receive buffer, sized for the largest
    /// expected datagram; the transport may use it as scratch space under the [`recv`]
    /// buffer contract, and its contents afterwards are unspecified. On success at least one
    /// datagram was appended, unless `datagrams` already held [`MAX_BATCH`], and
    /// `datagrams` never grows past [`MAX_BATCH`]. Once the transport is closed this
    /// returns [`io::ErrorKind::BrokenPipe`]; datagrams appended before an error are kept.
    ///
    /// The default receives one datagram with [`recv`] into `buf` and appends a copy of it,
    /// so a transport that cannot receive several at once needs nothing more. Cancellation
    /// safety is that of [`recv`]: the default appends a datagram only once [`recv`]
    /// resolved.
    ///
    /// [`recv`]: Transport::recv
    fn recv_batch(
        &self,
        buf: &mut PacketBuf,
        datagrams: &mut VecDeque<(Path, PacketBuf)>,
    ) -> impl Future<Output = io::Result<()>> + Send {
        async move {
            if datagrams.len() < MAX_BATCH {
                let (len, path) = self.recv(buf).await?;
                datagrams.push_back((path, PacketBuf::from_packet(&buf.as_packet()[..len])));
            }
            Ok(())
        }
    }

    /// Sends `datagrams[*sent..]` in order, each to its [`Path`] as with [`send`], advancing
    /// `*sent` past every datagram it is done with.
    ///
    /// The caller keeps the buffers (and reuses them once the call returns), so a batch
    /// costs no allocation; a transport may send a run of datagrams to the same path as
    /// one segmented send. A datagram counts as done once it was handed off or failed.
    /// On success every datagram is done (`*sent == datagrams.len()`). On an error the
    /// datagrams that failed are done and dropped, and the error is returned: after
    /// [`io::ErrorKind::BrokenPipe`] (the transport is closed) the caller stops, after any
    /// other error it may call again to send the rest. Delivery is best effort and should
    /// not wait indefinitely, as for [`send`].
    ///
    /// Cancellation safe: when the future is dropped, `*sent` counts the datagrams that
    /// were handed off and the rest were not sent, so the caller can hand them elsewhere
    /// in order.
    ///
    /// The default calls [`send`] for each datagram in order.
    ///
    /// [`send`]: Transport::send
    fn send_batch(
        &self,
        datagrams: &[(Path, PacketBuf)],
        sent: &mut usize,
    ) -> impl Future<Output = io::Result<()>> + Send {
        async move {
            while let Some((path, data)) = datagrams.get(*sent) {
                let result = self.send(data.as_packet(), path).await;
                *sent += 1;
                result?;
            }
            Ok(())
        }
    }
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
/// per call, so pass concrete transports where their type is known.
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

    /// [`Transport::recv_batch`] with a boxed future.
    fn recv_batch<'a>(
        &'a self,
        buf: &'a mut PacketBuf,
        datagrams: &'a mut VecDeque<(Path, PacketBuf)>,
    ) -> BoxFuture<'a, io::Result<()>>;

    /// [`Transport::send_batch`] with a boxed future.
    fn send_batch<'a>(
        &'a self,
        datagrams: &'a [(Path, PacketBuf)],
        sent: &'a mut usize,
    ) -> BoxFuture<'a, io::Result<()>>;
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

    fn recv_batch<'a>(
        &'a self,
        buf: &'a mut PacketBuf,
        datagrams: &'a mut VecDeque<(Path, PacketBuf)>,
    ) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(Transport::recv_batch(self, buf, datagrams))
    }

    fn send_batch<'a>(
        &'a self,
        datagrams: &'a [(Path, PacketBuf)],
        sent: &'a mut usize,
    ) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(Transport::send_batch(self, datagrams, sent))
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

    async fn recv_batch(
        &self,
        buf: &mut PacketBuf,
        datagrams: &mut VecDeque<(Path, PacketBuf)>,
    ) -> io::Result<()> {
        (**self).recv_batch(buf, datagrams).await
    }

    async fn send_batch(
        &self,
        datagrams: &[(Path, PacketBuf)],
        sent: &mut usize,
    ) -> io::Result<()> {
        (**self).send_batch(datagrams, sent).await
    }
}
