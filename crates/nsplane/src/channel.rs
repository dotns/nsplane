//! In-memory implementations of the driver traits on bounded tokio channels.

use std::io;
use std::net::SocketAddr;

use nsplane_packet::{Ecn, PacketBuf, Path, PeerId, TransportId};
use tokio::sync::{Mutex, mpsc, watch};

use crate::io::{PacketSink, PacketSource};
use crate::transport::Transport;

/// The error every channel type returns once its other end is gone.
fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "channel closed")
}

/// A [`PacketSource`] fed through an [`mpsc::Sender`].
#[derive(Debug)]
pub struct ChannelSource {
    rx: mpsc::Receiver<PacketBuf>,
    mtu: watch::Receiver<u16>,
}

impl ChannelSource {
    /// Creates a source queueing up to `capacity` packets, with an initial `mtu`.
    ///
    /// Returns the source, the sender that feeds it, and the sender that changes its MTU.
    /// Once every packet sender is dropped and the queue is drained, `recv` returns
    /// [`io::ErrorKind::BrokenPipe`].
    pub fn new(capacity: usize, mtu: u16) -> (Self, mpsc::Sender<PacketBuf>, watch::Sender<u16>) {
        let (tx, rx) = mpsc::channel(capacity);
        let (mtu_tx, mtu_rx) = watch::channel(mtu);
        (Self { rx, mtu: mtu_rx }, tx, mtu_tx)
    }
}

impl PacketSource for ChannelSource {
    async fn recv(&mut self) -> io::Result<PacketBuf> {
        self.rx.recv().await.ok_or_else(closed)
    }

    fn mtu(&self) -> watch::Receiver<u16> {
        self.mtu.clone()
    }
}

/// A [`PacketSink`] that delivers into an [`mpsc::Receiver`].
#[derive(Debug, Clone)]
pub struct ChannelSink {
    tx: mpsc::Sender<(PeerId, PacketBuf)>,
}

impl ChannelSink {
    /// Creates a sink queueing up to `capacity` packets.
    ///
    /// `send` waits while the queue is full and returns [`io::ErrorKind::BrokenPipe`]
    /// once the returned receiver is dropped.
    pub fn new(capacity: usize) -> (Self, mpsc::Receiver<(PeerId, PacketBuf)>) {
        let (tx, rx) = mpsc::channel(capacity);
        (Self { tx }, rx)
    }
}

impl PacketSink for ChannelSink {
    async fn send(&self, packet: PacketBuf, from: PeerId) -> io::Result<()> {
        self.tx.send((from, packet)).await.map_err(|_| closed())
    }
}

/// One end of an in-memory datagram link between two addresses.
///
/// A datagram sent to the peer's address arrives at the peer with
/// `Path { transport: <peer's id>, addr: <sender's address>, ecn: to.ecn }`, so ECN
/// marks survive the link. A datagram sent to any other address is silently dropped
/// and counts as sent, like UDP to nowhere. `to.transport` is not inspected.
#[derive(Debug)]
pub struct ChannelTransport {
    id: TransportId,
    local: SocketAddr,
    peer: SocketAddr,
    tx: mpsc::Sender<(Vec<u8>, Ecn)>,
    rx: Mutex<mpsc::Receiver<(Vec<u8>, Ecn)>>,
}

impl ChannelTransport {
    /// Creates a linked pair of transports `(a, b)`, each queueing up to `capacity`
    /// datagrams. `a` and `b` are each end's transport id and local address.
    ///
    /// Once one end is dropped, the other end's `send` to it and its `recv` (after the
    /// queue drains) return [`io::ErrorKind::BrokenPipe`].
    pub fn pair(
        capacity: usize,
        a: (TransportId, SocketAddr),
        b: (TransportId, SocketAddr),
    ) -> (Self, Self) {
        let (a_tx, b_rx) = mpsc::channel(capacity);
        let (b_tx, a_rx) = mpsc::channel(capacity);
        let a_end = Self {
            id: a.0,
            local: a.1,
            peer: b.1,
            tx: a_tx,
            rx: Mutex::new(a_rx),
        };
        let b_end = Self {
            id: b.0,
            local: b.1,
            peer: a.1,
            tx: b_tx,
            rx: Mutex::new(b_rx),
        };
        (a_end, b_end)
    }

    /// This end's address, the source address the peer sees.
    pub const fn local_addr(&self) -> SocketAddr {
        self.local
    }
}

impl Transport for ChannelTransport {
    fn id(&self) -> TransportId {
        self.id
    }

    async fn recv(&self, buf: &mut PacketBuf) -> io::Result<(usize, Path)> {
        let (datagram, ecn) = self.rx.lock().await.recv().await.ok_or_else(closed)?;
        let len = datagram.len().min(buf.capacity());
        // Only the datagram's length: growing to the capacity would zero-fill the whole
        // buffer (64 KiB in the engine) for every datagram.
        buf.set_len(len);
        buf.as_packet_mut().copy_from_slice(&datagram[..len]);
        let path = Path {
            transport: self.id,
            addr: self.peer,
            ecn,
        };
        Ok((len, path))
    }

    async fn send(&self, datagram: &[u8], to: &Path) -> io::Result<()> {
        if to.addr != self.peer {
            return Ok(());
        }
        self.tx
            .send((datagram.to_vec(), to.ecn))
            .await
            .map_err(|_| closed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nsplane_packet::HEADROOM;
    use std::time::Duration;
    use tokio::time::timeout;

    const PENDING: Duration = Duration::from_millis(50);

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn link() -> (ChannelTransport, ChannelTransport) {
        ChannelTransport::pair(
            8,
            (TransportId::new(1), addr("192.0.2.1:1000")),
            (TransportId::new(2), addr("[2001:db8::2]:2000")),
        )
    }

    fn path_to(transport: &ChannelTransport, ecn: Ecn) -> Path {
        Path {
            transport: transport.id(),
            addr: transport.local_addr(),
            ecn,
        }
    }

    /// Sends `datagram` from `from` to `to` and checks what `to` receives, through the
    /// trait only.
    async fn roundtrip<T: Transport>(from: &T, to: &T, to_path: &Path, expected: &Path) {
        let datagram = b"wireguard datagram";
        from.send(datagram, to_path).await.unwrap();
        let mut buf = PacketBuf::with_capacity(1500);
        let (len, path) = to.recv(&mut buf).await.unwrap();
        assert_eq!(len, datagram.len());
        assert_eq!(buf.as_packet(), datagram);
        assert_eq!(&path, expected);
    }

    #[tokio::test]
    async fn source_yields_in_order() {
        let (mut source, tx, _mtu) = ChannelSource::new(4, 1420);
        for i in 0..3u8 {
            tx.send(PacketBuf::from_packet(&[i])).await.unwrap();
        }
        for i in 0..3u8 {
            assert_eq!(source.recv().await.unwrap().as_packet(), [i]);
        }
    }

    #[tokio::test]
    async fn source_mtu_updates() {
        let (source, _tx, mtu_tx) = ChannelSource::new(1, 1420);
        let mut mtu = source.mtu();
        assert_eq!(*mtu.borrow(), 1420);
        mtu_tx.send(1280).unwrap();
        mtu.changed().await.unwrap();
        assert_eq!(*mtu.borrow_and_update(), 1280);
        assert_eq!(*source.mtu().borrow(), 1280);
    }

    #[tokio::test]
    async fn source_ends_after_senders_drop() {
        let (mut source, tx, _mtu) = ChannelSource::new(2, 1420);
        tx.send(PacketBuf::from_packet(&[7])).await.unwrap();
        drop(tx);
        assert_eq!(source.recv().await.unwrap().as_packet(), [7]);
        for _ in 0..2 {
            let err = source.recv().await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        }
    }

    #[tokio::test]
    async fn sink_delivers_with_peer() {
        let (sink, mut rx) = ChannelSink::new(2);
        sink.send(PacketBuf::from_packet(&[1, 2]), PeerId::new(5))
            .await
            .unwrap();
        let (peer, packet) = rx.recv().await.unwrap();
        assert_eq!(peer, PeerId::new(5));
        assert_eq!(packet.as_packet(), [1, 2]);
    }

    #[tokio::test]
    async fn sink_closed() {
        let (sink, rx) = ChannelSink::new(1);
        drop(rx);
        let err = sink
            .send(PacketBuf::from_packet(&[1]), PeerId::new(1))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn sink_backpressure() {
        let (sink, mut rx) = ChannelSink::new(1);
        sink.send(PacketBuf::from_packet(&[1]), PeerId::new(1))
            .await
            .unwrap();
        let mut pending = Box::pin(sink.send(PacketBuf::from_packet(&[2]), PeerId::new(2)));
        assert!(timeout(PENDING, &mut pending).await.is_err());

        assert_eq!(rx.recv().await.unwrap().1.as_packet(), [1]);
        timeout(Duration::from_secs(5), pending)
            .await
            .unwrap()
            .unwrap();
        let (peer, packet) = rx.recv().await.unwrap();
        assert_eq!(peer, PeerId::new(2));
        assert_eq!(packet.as_packet(), [2]);
    }

    #[tokio::test]
    async fn transport_both_directions() {
        let (a, b) = link();
        let from_a = Path {
            transport: b.id(),
            addr: a.local_addr(),
            ecn: Ecn::NotEct,
        };
        roundtrip(&a, &b, &path_to(&b, Ecn::NotEct), &from_a).await;
        let from_b = Path {
            transport: a.id(),
            addr: b.local_addr(),
            ecn: Ecn::NotEct,
        };
        roundtrip(&b, &a, &path_to(&a, Ecn::NotEct), &from_b).await;
    }

    #[tokio::test]
    async fn transport_preserves_ecn() {
        let (a, b) = link();
        for ecn in [Ecn::NotEct, Ecn::Ect1, Ecn::Ect0, Ecn::Ce] {
            let expected = Path {
                transport: TransportId::new(2),
                addr: addr("192.0.2.1:1000"),
                ecn,
            };
            roundtrip(&a, &b, &path_to(&b, ecn), &expected).await;
        }
    }

    #[tokio::test]
    async fn transport_drops_wrong_address() {
        let (a, b) = link();
        let nowhere = Path {
            transport: b.id(),
            addr: addr("198.51.100.9:9"),
            ecn: Ecn::NotEct,
        };
        a.send(b"lost", &nowhere).await.unwrap();
        a.send(b"kept", &path_to(&b, Ecn::NotEct)).await.unwrap();
        let mut buf = PacketBuf::with_capacity(64);
        let (len, _) = b.recv(&mut buf).await.unwrap();
        assert_eq!(&buf.as_packet()[..len], b"kept");
    }

    #[tokio::test]
    async fn transport_truncates_and_keeps_headroom() {
        let (a, b) = link();
        let datagram: Vec<u8> = (0..=255).collect();
        a.send(&datagram, &path_to(&b, Ecn::Ce)).await.unwrap();

        let mut buf = PacketBuf::with_capacity(16);
        buf.with_headroom_mut()[..HEADROOM].fill(0xAA);
        let capacity = buf.capacity();
        assert!(capacity < datagram.len());

        let (len, path) = b.recv(&mut buf).await.unwrap();
        assert_eq!(len, capacity);
        assert_eq!(buf.len(), capacity);
        assert_eq!(buf.as_packet(), &datagram[..capacity]);
        assert_eq!(path.ecn, Ecn::Ce);
        assert!(
            buf.with_headroom_mut()[..HEADROOM]
                .iter()
                .all(|&b| b == 0xAA)
        );
    }

    #[tokio::test]
    async fn transport_closed() {
        let (a, b) = link();
        let to_b = path_to(&b, Ecn::NotEct);
        drop(b);
        let err = a.send(b"x", &to_b).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        let err = a.recv(&mut PacketBuf::with_capacity(8)).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }
}
