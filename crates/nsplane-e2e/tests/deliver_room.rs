//! The deliver-room gate without crypto workers: the engine reads received datagrams only
//! while its deliver queue has room for what they may deliver, so a sink slower than the
//! network holds the datagrams back in the transport instead of dropping decrypted packets
//! under `DROP_SINK_FULL`.
//!
//! The receiving engine delivers into a pipe, whose `try_send_batch` lets its owner task
//! deliver itself while the pipe has room; the test stops reading the pipe for a while and
//! then drains it. Over an in-memory link the held-back datagrams back up into the sender,
//! which holds back its source, so every packet arrives, in order. Over UDP they back up in
//! the receiver's socket buffer, which drops what does not fit, but nothing is dropped as
//! sink-full and what arrives is in order.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::Range;

use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{
    AllowedIp, ChannelSource, ChannelTransport, DROP_SINK_FULL, Ecn, Engine, EngineBuilder,
    EngineHandle, PacketBuf, PacketSource, Path, Peer, PipeSource, Transport, TransportId,
    UdpTransport, pipe,
};
use nsplane_e2e::{MTU, Node, Options, QUIET, TestResult, WAIT, udp4};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

/// The receiver's queue capacity: its deliver queue holds this many packets.
const QUEUE: usize = 16;
/// Packets the receiver's pipe holds.
const PIPE: usize = 4;
/// The receiver's key seed and tunnel address.
const SEED: u8 = 2;
const IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, SEED);

/// An engine that delivers into a pipe, and the reading end of the pipe.
struct Receiver {
    _engine: Engine,
    handle: EngineHandle,
    pipe: PipeSource,
    path: Path,
}

impl Receiver {
    fn new<T: Transport>(id: TransportId, addr: SocketAddr, transport: T) -> TestResult<Self> {
        let (source, _local, _mtu) = ChannelSource::new(4, MTU);
        let (sink, pipe) = pipe(PIPE, MTU);
        let engine = EngineBuilder::new(source, sink)
            .transport(transport)
            .private_key(StaticSecret::from([SEED; 32]))
            .queue_capacity(QUEUE)
            .build()?;
        Ok(Self {
            handle: engine.handle(),
            _engine: engine,
            pipe,
            path: Path {
                transport: id,
                addr,
                ecn: Ecn::NotEct,
            },
        })
    }

    /// Makes `sender` and the receiver peers of each other.
    async fn introduce<T: Transport>(&self, sender: &Node<T>) -> TestResult {
        let secret = StaticSecret::from([SEED; 32]);
        sender
            .handle
            .add_or_update_peer(Peer {
                allowed_ips: vec![AllowedIp {
                    addr: IpAddr::V4(IP),
                    cidr: 32,
                }],
                path: Some(Path {
                    transport: sender.path.transport,
                    ..self.path
                }),
                ..Peer::new(PublicKey::from(&secret))
            })
            .await?;
        self.handle
            .add_or_update_peer(sender.as_peer(self.path.transport))
            .await?;
        Ok(())
    }

    /// The sequence number of the next delivered packet, within [`WAIT`].
    async fn next(&mut self) -> TestResult<u32> {
        seq(&timeout(WAIT, self.pipe.recv()).await??)
    }

    /// The sequence numbers delivered until the pipe stays empty for [`QUIET`].
    async fn drain(&mut self) -> TestResult<Vec<u32>> {
        let mut seqs = Vec::new();
        while let Ok(packet) = timeout(QUIET, self.pipe.recv()).await {
            seqs.push(seq(&packet?)?);
        }
        Ok(seqs)
    }

    async fn sink_full(&self) -> TestResult<u64> {
        let counters = self.handle.drop_counters().await?;
        Ok(counters.get(DROP_SINK_FULL).copied().unwrap_or(0))
    }
}

/// The sequence number a packet of [`numbered`] carries.
fn seq(packet: &PacketBuf) -> TestResult<u32> {
    let packet = packet.as_packet();
    let tail = packet
        .get(packet.len().saturating_sub(4)..)
        .and_then(|tail| <[u8; 4]>::try_from(tail).ok())
        .ok_or("short packet")?;
    Ok(u32::from_be_bytes(tail))
}

/// A packet from `sender` to the receiver numbered `seq`.
fn numbered<T: Transport>(sender: &Node<T>, seq: u32) -> Vec<u8> {
    udp4(sender.ip4, IP, &seq.to_be_bytes())
}

/// Hands the packets numbered `range` to `sender`'s source, waiting while it is full.
fn send_all<T: Transport>(sender: &Node<T>, range: Range<u32>) -> JoinHandle<TestResult> {
    let local = sender.local.clone();
    let packets: Vec<_> = range.map(|seq| numbered(sender, seq)).collect();
    tokio::spawn(async move {
        for packet in packets {
            local.send(PacketBuf::from_packet(&packet)).await?;
        }
        Ok(())
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocked_sink_holds_back_the_sender() -> TestResult {
    // More than the sender's queues and the link hold.
    const PACKETS: u32 = 4000;
    let a_end = (
        TransportId::new(1),
        SocketAddr::from(([192, 0, 2, 1], 1000)),
    );
    let b_end = (
        TransportId::new(2),
        SocketAddr::from(([192, 0, 2, 2], 2000)),
    );
    let (link_a, link_b) = ChannelTransport::pair(64, a_end, b_end);
    let sender = Node::new(1, a_end.0, a_end.1, link_a, Options::default());
    let mut receiver = Receiver::new(b_end.0, b_end.1, link_b)?;
    receiver.introduce(&sender).await?;
    send_all(&sender, 0..1).await??;
    assert_eq!(receiver.next().await?, 0);

    // Nothing reads the pipe: the datagrams back up through the link into the sender, which
    // holds back its source.
    let sending = send_all(&sender, 1..PACKETS);
    sleep(QUIET).await;
    assert!(!sending.is_finished(), "the sender was not held back");
    assert!(receiver.handle.drop_counters().await?.is_empty());
    for seq in 1..PACKETS {
        assert_eq!(receiver.next().await?, seq);
    }
    timeout(WAIT, sending).await???;
    assert!(receiver.handle.drop_counters().await?.is_empty());
    assert!(sender.handle.drop_counters().await?.is_empty());
    let deliver = receiver.handle.queue_stats().await?.deliver;
    assert!(deliver.high_water <= deliver.capacity, "{deliver:?}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocked_sink_leaves_udp_datagrams_in_the_socket() -> TestResult {
    const PACKETS: u32 = 2000;
    let localhost = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let a = UdpTransport::bind(TransportId::new(1), SocketAddr::new(localhost, 0))?;
    let a_addr = a.local_addr();
    let b = UdpTransport::bind(TransportId::new(2), SocketAddr::new(localhost, 0))?;
    let b_addr = b.local_addr();
    let sender = Node::new(1, TransportId::new(1), a_addr, a, Options::default());
    let mut receiver = Receiver::new(TransportId::new(2), b_addr, b)?;
    receiver.introduce(&sender).await?;
    send_all(&sender, 0..1).await??;
    assert_eq!(receiver.next().await?, 0);

    // Nothing reads the pipe while the sender sends everything: what the socket's buffer
    // does not hold is lost there, not decrypted into a full deliver queue.
    let sending = send_all(&sender, 1..PACKETS);
    sleep(QUIET).await;
    timeout(WAIT, sending).await???;
    let seqs = receiver.drain().await?;
    assert!(!seqs.is_empty(), "nothing delivered after the stall");
    assert!(
        seqs.windows(2).all(|pair| pair[0] < pair[1]),
        "out of order"
    );
    assert_eq!(receiver.sink_full().await?, 0);

    // The session survives the stall.
    send_all(&sender, PACKETS..PACKETS + 1).await??;
    assert_eq!(receiver.next().await?, PACKETS);
    Ok(())
}
