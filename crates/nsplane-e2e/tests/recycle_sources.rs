//! Buffers recycled through a `MergeSource` reach its pooled sources, which read the next
//! packets into them; a `TunSlot` source reads into a buffer recycled to it; and a
//! `host_tun` input copies the host's packets into the buffers its engine recycled.

use std::collections::HashSet;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use nsplane::{MergeSource, PacketBuf, PacketPool, PacketSource};
use nsplane_e2e::{TestResult, WAIT};
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;

const MTU: u16 = 1420;

/// A source that copies each payload it is sent into a pooled buffer and counts the reads
/// served from recycled buffers.
struct Pooled {
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    pool: PacketPool,
    hits: Arc<AtomicU64>,
    mtu: watch::Sender<u16>,
}

impl Pooled {
    fn new() -> (Self, mpsc::UnboundedSender<Vec<u8>>, Arc<AtomicU64>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let hits = Arc::new(AtomicU64::new(0));
        let source = Self {
            rx,
            pool: PacketPool::new(8),
            hits: Arc::clone(&hits),
            mtu: watch::Sender::new(MTU),
        };
        (source, tx, hits)
    }
}

impl PacketSource for Pooled {
    async fn recv(&mut self) -> io::Result<PacketBuf> {
        let payload = self
            .rx
            .recv()
            .await
            .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))?;
        if self.pool.free_len() > 0 {
            self.hits.fetch_add(1, Ordering::Relaxed);
        }
        let mut packet = self.pool.get(usize::from(MTU));
        packet.extend_from_slice(&payload);
        Ok(packet)
    }

    fn recycle(&mut self, bufs: &mut Vec<PacketBuf>) {
        for buf in bufs.drain(..) {
            self.pool.put(buf);
        }
    }

    fn mtu(&self) -> watch::Receiver<u16> {
        self.mtu.subscribe()
    }
}

/// Receives one packet from `merge` and checks its payload; returns its address.
async fn recv(merge: &mut MergeSource, payload: &[u8]) -> TestResult<(PacketBuf, *const u8)> {
    let packet = timeout(WAIT, merge.recv()).await??;
    assert_eq!(packet.as_packet(), payload);
    let addr = packet.as_packet().as_ptr();
    Ok((packet, addr))
}

#[tokio::test]
async fn merge_hands_recycled_buffers_to_its_sources() -> TestResult {
    let (a, a_tx, a_hits) = Pooled::new();
    let (b, b_tx, b_hits) = Pooled::new();
    let mut merge = MergeSource::new().source(a).source(b);

    for (tx, hits) in [(&a_tx, &a_hits), (&b_tx, &b_hits)] {
        // The first read allocates.
        tx.send(b"first".to_vec())?;
        let (first, addr) = recv(&mut merge, b"first").await?;
        assert_eq!(hits.load(Ordering::Relaxed), 0);
        merge.recycle(&mut vec![first]);

        // Read before the source got the buffer, so it allocates; then the source takes it.
        tx.send(b"second".to_vec())?;
        let (_second, _) = recv(&mut merge, b"second").await?;
        assert_eq!(hits.load(Ordering::Relaxed), 0);

        tx.send(b"third".to_vec())?;
        let (_third, reused) = recv(&mut merge, b"third").await?;
        assert_eq!(hits.load(Ordering::Relaxed), 1);
        assert_eq!(reused, addr, "the recycled buffer is read into again");
    }
    Ok(())
}

#[tokio::test]
async fn merge_without_recycle_allocates_every_read() -> TestResult {
    let (a, a_tx, a_hits) = Pooled::new();
    let (b, b_tx, b_hits) = Pooled::new();
    let mut merge = MergeSource::new().source(a).source(b);

    // Held, so no address is freed and handed out again.
    let mut held = Vec::new();
    for n in 0..4u8 {
        a_tx.send(vec![n])?;
        b_tx.send(vec![n])?;
        for _ in 0..2 {
            held.push(recv(&mut merge, &[n]).await?.0);
        }
    }
    let addrs: HashSet<_> = held.iter().map(|p| p.as_packet().as_ptr()).collect();
    assert_eq!(addrs.len(), 8);
    assert_eq!(a_hits.load(Ordering::Relaxed), 0);
    assert_eq!(b_hits.load(Ordering::Relaxed), 0);
    Ok(())
}

/// No root needed: the slot's fd is one end of a datagram socket pair.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn slot_source_reads_into_a_recycled_buffer() -> TestResult {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixDatagram;

    use nsplane_tun::TunSlot;

    let (slot, mut source, _sink) = TunSlot::new(MTU);
    let (fd, host) = UnixDatagram::pair()?;
    slot.replace(OwnedFd::from(fd))?;

    host.send(b"first")?;
    let first = timeout(WAIT, source.recv()).await??;
    assert_eq!(first.as_packet(), b"first");
    let addr = first.as_packet().as_ptr();
    source.recycle(&mut vec![first]);

    host.send(b"second")?;
    let second = timeout(WAIT, source.recv()).await??;
    assert_eq!(second.as_packet(), b"second");
    assert_eq!(second.as_packet().as_ptr(), addr);
    Ok(())
}

#[cfg(target_os = "linux")]
mod host {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use nsplane::x25519::{PublicKey, StaticSecret};
    use nsplane::{
        AllowedIp, ChannelTransport, Ecn, EngineBuilder, PacketBatch, Path, Peer, TransportId,
    };
    use nsplane_e2e::{Node, Options, payload, udp4};
    use nsplane_tun::{HOST_TUN_DEFAULT_CAPACITY, HostTunSource, host_tun};

    use super::*;

    /// A `HostTunSource` that records the buffers recycled to it and counts the packets it
    /// read into one of them.
    struct Watched {
        inner: HostTunSource,
        recycled: HashSet<usize>,
        reused: Arc<AtomicU64>,
    }

    impl Watched {
        /// The address of `packet`'s allocation, whatever its headroom.
        fn base(packet: &mut PacketBuf) -> usize {
            packet.with_headroom_mut().as_ptr() as usize
        }

        fn note(&mut self, packet: &mut PacketBuf) {
            if self.recycled.remove(&Self::base(packet)) {
                self.reused.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    impl PacketSource for Watched {
        async fn recv(&mut self) -> io::Result<PacketBuf> {
            let mut packet = self.inner.recv().await?;
            self.note(&mut packet);
            Ok(packet)
        }

        async fn recv_batch(&mut self, batch: &mut PacketBatch) -> io::Result<()> {
            let before = batch.len();
            self.inner.recv_batch(batch).await?;
            let mut packets: Vec<_> = batch.drain().collect();
            for packet in &mut packets[before..] {
                self.note(packet);
            }
            for packet in packets {
                let _ = batch.push(packet);
            }
            Ok(())
        }

        fn recycle(&mut self, bufs: &mut Vec<PacketBuf>) {
            self.recycled.extend(bufs.iter_mut().map(Self::base));
            self.inner.recycle(bufs);
        }

        fn mtu(&self) -> watch::Receiver<u16> {
            self.inner.mtu()
        }
    }

    #[tokio::test]
    async fn host_tun_pushes_into_buffers_the_engine_recycled() -> TestResult {
        const SEED: u8 = 1;
        let ip4 = Ipv4Addr::new(10, 0, 0, SEED);
        let a = (
            TransportId::new(1),
            SocketAddr::from(([192, 0, 2, 1], 1000)),
        );
        let b = (
            TransportId::new(2),
            SocketAddr::from(([192, 0, 2, 2], 2000)),
        );
        let (link_a, link_b) = ChannelTransport::pair(1024, a, b);
        let (input, source, sink) =
            host_tun(MTU, HOST_TUN_DEFAULT_CAPACITY, Arc::new(|_: &[u8]| true));
        let reused = Arc::new(AtomicU64::new(0));
        let source = Watched {
            inner: source,
            recycled: HashSet::new(),
            reused: Arc::clone(&reused),
        };
        let engine = EngineBuilder::new(source, sink)
            .private_key(StaticSecret::from([SEED; 32]))
            .transport(link_a)
            .build()?;
        let mut node = Node::new(2, b.0, b.1, link_b, Options::default());
        engine
            .handle()
            .add_or_update_peer(node.as_peer(a.0))
            .await?;
        node.handle
            .add_or_update_peer(Peer {
                allowed_ips: vec![AllowedIp {
                    addr: IpAddr::V4(ip4),
                    cidr: 32,
                }],
                path: Some(Path {
                    transport: b.0,
                    addr: a.1,
                    ecn: Ecn::NotEct,
                }),
                ..Peer::new(PublicKey::from(&StaticSecret::from([SEED; 32])))
            })
            .await?;

        // One packet at a time: each one's buffer is recycled while the next is read, so the
        // pushes from the third on copy into a recycled buffer.
        for n in 0..16 {
            let packet = udp4(ip4, node.ip4, &payload(100 + n));
            input.push(&packet)?;
            assert_eq!(node.expect_delivery().await?.1, packet);
        }
        let reused = reused.load(Ordering::Relaxed);
        assert!(reused >= 8, "{reused} pushes reused a buffer");
        Ok(())
    }
}
