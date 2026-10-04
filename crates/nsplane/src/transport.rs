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
    /// `*sent` past every datagram it is done with and `*failed` by every one of those that
    /// failed.
    ///
    /// The caller keeps the buffers (and reuses them once the call returns), so a batch
    /// costs no allocation; a transport may send a run of datagrams to the same path as
    /// one segmented send. A datagram counts as done once it was handed off or failed; a
    /// failed one is dropped, and `*failed` never grows by more than `*sent` does. On
    /// success every datagram is done (`*sent == datagrams.len()`) and none of this call
    /// failed. On an error at least the last datagram the call was done with failed, and
    /// the error is returned: after [`io::ErrorKind::BrokenPipe`] (the transport is closed)
    /// the caller stops, after any other error it may call again to send the rest. A failed
    /// segmented send fails exactly the datagrams of its run, not the ones handed off
    /// before it. Delivery is best effort and should not wait indefinitely, as for [`send`].
    ///
    /// Cancellation safe: when the future is dropped, `*sent` counts the datagrams that
    /// were handed off and the rest were not sent, so the caller can hand them elsewhere
    /// in order.
    ///
    /// The default calls [`send`] for each datagram in order and counts a failed one in
    /// `*failed`.
    ///
    /// [`send`]: Transport::send
    fn send_batch(
        &self,
        datagrams: &[(Path, PacketBuf)],
        sent: &mut usize,
        failed: &mut usize,
    ) -> impl Future<Output = io::Result<()>> + Send {
        async move {
            while let Some((path, data)) = datagrams.get(*sent) {
                let result = self.send(data.as_packet(), path).await;
                *sent += 1;
                result.inspect_err(|_| *failed += 1)?;
            }
            Ok(())
        }
    }

    /// Hands off `datagrams[*sent..]` like [`send_batch`], but never waits.
    ///
    /// Synchronous: the call returns as soon as it would have to wait, so the engine may
    /// call it from its owner task when the transport's transmit task is idle, saving the
    /// handoff to that task. The datagrams go out in order, and `*sent` and `*failed` are
    /// advanced as with [`send_batch`] (a failed one is done and dropped, a failed segmented
    /// send fails its run, [`io::ErrorKind::BrokenPipe`] means the transport is closed).
    /// When the next datagram cannot be handed off now, this returns
    /// [`io::ErrorKind::WouldBlock`] with `*sent` just before it and that datagram neither
    /// sent nor failed: the caller keeps the rest (`datagrams[*sent..]`) and sends it
    /// later, after the ones before it. On success every datagram is done.
    ///
    /// The default hands off nothing and returns [`io::ErrorKind::WouldBlock`], so the
    /// engine sends every datagram through [`send_batch`] on the transmit task.
    ///
    /// [`send_batch`]: Transport::send_batch
    fn try_send_batch(
        &self,
        datagrams: &[(Path, PacketBuf)],
        sent: &mut usize,
        failed: &mut usize,
    ) -> io::Result<()> {
        let _ = (datagrams, sent, failed);
        Err(io::ErrorKind::WouldBlock.into())
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
        failed: &'a mut usize,
    ) -> BoxFuture<'a, io::Result<()>>;

    /// [`Transport::try_send_batch`].
    fn try_send_batch(
        &self,
        datagrams: &[(Path, PacketBuf)],
        sent: &mut usize,
        failed: &mut usize,
    ) -> io::Result<()>;
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
        failed: &'a mut usize,
    ) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(Transport::send_batch(self, datagrams, sent, failed))
    }

    fn try_send_batch(
        &self,
        datagrams: &[(Path, PacketBuf)],
        sent: &mut usize,
        failed: &mut usize,
    ) -> io::Result<()> {
        Transport::try_send_batch(self, datagrams, sent, failed)
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
        failed: &mut usize,
    ) -> io::Result<()> {
        (**self).send_batch(datagrams, sent, failed).await
    }

    fn try_send_batch(
        &self,
        datagrams: &[(Path, PacketBuf)],
        sent: &mut usize,
        failed: &mut usize,
    ) -> io::Result<()> {
        (**self).try_send_batch(datagrams, sent, failed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Hands off a datagram whose first byte is even and fails the others; keeps the
    /// handed-off first bytes.
    #[derive(Debug, Default)]
    struct OddFails(Mutex<Vec<u8>>);

    impl Transport for OddFails {
        fn id(&self) -> TransportId {
            TransportId::new(1)
        }

        async fn recv(&self, _buf: &mut PacketBuf) -> io::Result<(usize, Path)> {
            std::future::pending().await
        }

        fn send(&self, datagram: &[u8], _to: &Path) -> impl Future<Output = io::Result<()>> + Send {
            std::future::ready(if datagram[0] % 2 == 1 {
                Err(io::Error::other("odd"))
            } else {
                self.0.lock().unwrap().push(datagram[0]);
                Ok(())
            })
        }
    }

    /// Calls `send_batch` past every error, as the engine does; returns how many calls
    /// failed and how many datagrams they reported failed.
    async fn send_past_errors<T: Transport>(
        transport: &T,
        datagrams: &[(Path, PacketBuf)],
    ) -> (usize, usize) {
        let (mut sent, mut failed, mut errors) = (0, 0, 0);
        while sent < datagrams.len() {
            let before = (sent, failed);
            if transport
                .send_batch(datagrams, &mut sent, &mut failed)
                .await
                .is_err()
            {
                errors += 1;
                assert!(failed > before.1, "an error fails at least one datagram");
            } else {
                assert_eq!(failed, before.1, "a success fails nothing");
                assert_eq!(sent, datagrams.len());
            }
            assert!(failed - before.1 <= sent - before.0);
        }
        (errors, failed)
    }

    fn datagrams(first_bytes: &[u8]) -> Vec<(Path, PacketBuf)> {
        let to = Path {
            transport: TransportId::new(1),
            addr: "192.0.2.1:1".parse().unwrap(),
            ecn: nsplane_packet::Ecn::NotEct,
        };
        first_bytes
            .iter()
            .map(|&byte| (to, PacketBuf::from_packet(&[byte])))
            .collect()
    }

    #[tokio::test]
    async fn default_send_batch_counts_each_failed_send() {
        let batch = datagrams(&[0, 1, 2, 3, 5, 4, 7]);
        let transport = OddFails::default();
        assert_eq!(send_past_errors(&transport, &batch).await, (4, 4));
        assert_eq!(*transport.0.lock().unwrap(), [0, 2, 4]);

        let boxed: Box<dyn DynTransport> = Box::new(OddFails::default());
        assert_eq!(send_past_errors(&boxed, &batch).await, (4, 4));
    }

    #[test]
    fn default_try_send_batch_hands_off_nothing() {
        let batch = datagrams(&[0, 2]);
        let transport = OddFails::default();
        let (mut sent, mut failed) = (0, 0);
        let error =
            Transport::try_send_batch(&transport, &batch, &mut sent, &mut failed).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!((sent, failed), (0, 0));
        assert!(transport.0.lock().unwrap().is_empty());

        let boxed: Box<dyn DynTransport> = Box::new(OddFails::default());
        let error = Transport::try_send_batch(&boxed, &batch, &mut sent, &mut failed).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!((sent, failed), (0, 0));
    }

    /// Hands off what a budget allows, then would block.
    #[derive(Debug, Default)]
    struct Budget(Mutex<usize>);

    impl Transport for Budget {
        fn id(&self) -> TransportId {
            TransportId::new(1)
        }

        async fn recv(&self, _buf: &mut PacketBuf) -> io::Result<(usize, Path)> {
            std::future::pending().await
        }

        fn send(
            &self,
            _datagram: &[u8],
            _to: &Path,
        ) -> impl Future<Output = io::Result<()>> + Send {
            std::future::ready(Ok(()))
        }

        fn try_send_batch(
            &self,
            datagrams: &[(Path, PacketBuf)],
            sent: &mut usize,
            _failed: &mut usize,
        ) -> io::Result<()> {
            let mut budget = self.0.lock().unwrap();
            while *sent < datagrams.len() {
                if *budget == 0 {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                *budget -= 1;
                *sent += 1;
            }
            Ok(())
        }
    }

    #[test]
    fn boxed_transport_forwards_try_send_batch() {
        let batch = datagrams(&[0, 2, 4]);
        let boxed: Box<dyn DynTransport> = Box::new(Budget(Mutex::new(2)));
        let (mut sent, mut failed) = (0, 0);
        let error = Transport::try_send_batch(&boxed, &batch, &mut sent, &mut failed).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!((sent, failed), (2, 0));
    }
}
