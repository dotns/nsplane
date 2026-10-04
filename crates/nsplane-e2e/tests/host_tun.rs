//! An engine whose local side is a `host_tun`, driven by a test host on a plain thread, peered
//! with a channel-transport node: packets in both directions, a host writer that closes and an
//! MTU set on the source after packets were queued, before the engine is built.

#![cfg(target_os = "linux")]

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{
    AllowedIp, ChannelTransport, DROP_SINK_CLOSED, Ecn, Engine, EngineBuilder, EngineHandle,
    PacketBatch, PacketBuf, PacketSource, Path, Peer, TransportId,
};
use nsplane_e2e::{Family, Node, Options, QUIET, TestResult, WAIT, payload, udp4, udp6};
use nsplane_tun::{HOST_TUN_DEFAULT_CAPACITY, HostTunInput, HostTunSource, host_tun};
use tokio::sync::{mpsc, watch};
use tokio::time::{sleep, timeout};

const SEED: u8 = 1;
const IP4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, SEED);
const IP6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);

/// An engine on a `host_tun` and the host's ends of it.
struct Host {
    _engine: Engine,
    handle: EngineHandle,
    input: HostTunInput,
    written: mpsc::UnboundedReceiver<Vec<u8>>,
}

impl Host {
    /// A UDP packet of `family` from the host's tunnel address to `node`'s.
    fn packet_to(node: &Node<ChannelTransport>, family: Family, len: usize) -> Vec<u8> {
        match family {
            Family::V4 => udp4(IP4, node.ip4, &payload(len)),
            Family::V6 => udp6(IP6, node.ip6, &payload(len)),
        }
    }

    /// Pushes `packets` from a plain (non-tokio) thread, as `NEPacketTunnelFlow` does.
    async fn push(&self, packets: Vec<Vec<u8>>) -> TestResult {
        let input = self.input.clone();
        let host = std::thread::spawn(move || {
            for packet in &packets {
                input.push(packet)?;
            }
            Ok::<_, nsplane_tun::PushError>(())
        });
        tokio::task::spawn_blocking(move || host.join())
            .await?
            .map_err(|_| "host thread panicked")??;
        Ok(())
    }

    /// The next packet the engine wrote to the host, within [`WAIT`].
    async fn expect_write(&mut self) -> TestResult<Vec<u8>> {
        timeout(WAIT, self.written.recv())
            .await?
            .ok_or_else(|| "host writer gone".into())
    }
}

/// A host engine (seed 1) and a channel node (seed 2), peers of each other; `write_open`
/// decides whether the host's writer still takes packets and `writes` counts its calls.
fn pair(
    write_open: Arc<AtomicBool>,
    writes: Arc<AtomicUsize>,
) -> TestResult<(Host, Node<ChannelTransport>)> {
    let a = (
        TransportId::new(1),
        SocketAddr::from(([192, 0, 2, 1], 1000)),
    );
    let b = (
        TransportId::new(2),
        SocketAddr::from(([192, 0, 2, 2], 2000)),
    );
    let (link_a, link_b) = ChannelTransport::pair(1024, a, b);

    let (tx, written) = mpsc::unbounded_channel();
    let (input, source, sink) = host_tun(
        nsplane_e2e::MTU,
        HOST_TUN_DEFAULT_CAPACITY,
        Arc::new(move |packet: &[u8]| {
            writes.fetch_add(1, Ordering::SeqCst);
            write_open.load(Ordering::SeqCst) && tx.send(packet.to_vec()).is_ok()
        }),
    );
    let engine = EngineBuilder::new(source, sink)
        .private_key(StaticSecret::from([SEED; 32]))
        .transport(link_a)
        .build()?;
    let host = Host {
        handle: engine.handle(),
        _engine: engine,
        input,
        written,
    };
    let node = Node::new(2, b.0, b.1, link_b, Options::default());
    Ok((host, node))
}

/// Makes the host and `node` peers of each other.
async fn introduce(host: &Host, node: &Node<ChannelTransport>) -> TestResult {
    host.handle
        .add_or_update_peer(node.as_peer(TransportId::new(1)))
        .await?;
    node.handle
        .add_or_update_peer(Peer {
            allowed_ips: vec![
                AllowedIp {
                    addr: IpAddr::V4(IP4),
                    cidr: 32,
                },
                AllowedIp {
                    addr: IpAddr::V6(IP6),
                    cidr: 128,
                },
            ],
            path: Some(Path {
                transport: TransportId::new(2),
                addr: SocketAddr::from(([192, 0, 2, 1], 1000)),
                ecn: Ecn::NotEct,
            }),
            ..Peer::new(PublicKey::from(&StaticSecret::from([SEED; 32])))
        })
        .await?;
    Ok(())
}

#[tokio::test]
async fn packets_flow_both_ways_in_order() -> TestResult {
    let (mut host, mut node) = pair(
        Arc::new(AtomicBool::new(true)),
        Arc::new(AtomicUsize::new(0)),
    )?;
    introduce(&host, &node).await?;

    for family in [Family::V4, Family::V6] {
        // One packet first, so the handshake is done before the run.
        let first = Host::packet_to(&node, family, 64);
        host.push(vec![first.clone()]).await?;
        assert_eq!(node.expect_delivery().await?.1, first);

        let packets: Vec<Vec<u8>> = [32, 200, 1300, 64]
            .into_iter()
            .map(|len| Host::packet_to(&node, family, len))
            .collect();
        host.push(packets.clone()).await?;
        for packet in &packets {
            assert_eq!(&node.expect_delivery().await?.1, packet);
        }

        let replies: Vec<Vec<u8>> = [32, 200, 1300, 64]
            .into_iter()
            .map(|len| match family {
                Family::V4 => udp4(node.ip4, IP4, &payload(len)),
                Family::V6 => udp6(node.ip6, IP6, &payload(len)),
            })
            .collect();
        for reply in &replies {
            node.send(reply).await?;
        }
        for reply in &replies {
            assert_eq!(&host.expect_write().await?, reply);
        }
    }
    Ok(())
}

#[tokio::test]
async fn a_closed_host_writer_stops_delivery() -> TestResult {
    let open = Arc::new(AtomicBool::new(true));
    let writes = Arc::new(AtomicUsize::new(0));
    let (mut host, mut node) = pair(Arc::clone(&open), Arc::clone(&writes))?;
    introduce(&host, &node).await?;

    let packet = udp4(node.ip4, IP4, b"before");
    node.send(&packet).await?;
    assert_eq!(host.expect_write().await?, packet);

    // The writer refuses the next packet: the sink reports BrokenPipe and stops.
    open.store(false, Ordering::SeqCst);
    node.send(&udp4(node.ip4, IP4, b"refused")).await?;
    timeout(WAIT, async {
        while writes.load(Ordering::SeqCst) < 2 {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;

    // Later packets never reach the writer; the engine drops them as the sink is closed.
    node.send(&udp4(node.ip4, IP4, b"after")).await?;
    timeout(WAIT, async {
        loop {
            let counters = host.handle.drop_counters().await?;
            if counters.get(DROP_SINK_CLOSED).copied().unwrap_or(0) > 0 {
                return TestResult::Ok(());
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    sleep(QUIET).await;
    assert_eq!(writes.load(Ordering::SeqCst), 2);

    // The engine keeps running: host packets still reach the node.
    let outbound = Host::packet_to(&node, Family::V4, 64);
    host.push(vec![outbound.clone()]).await?;
    assert_eq!(node.expect_delivery().await?.1, outbound);
    Ok(())
}

/// A `HostTunSource` the engine reads only once `open` turns true, so packets the host
/// queued wait until the test made the peers known.
struct Gated {
    source: HostTunSource,
    open: watch::Receiver<bool>,
}

impl Gated {
    async fn wait_open(&mut self) -> io::Result<()> {
        self.open
            .wait_for(|open| *open)
            .await
            .map(|_| ())
            .map_err(|_| io::ErrorKind::BrokenPipe.into())
    }
}

impl PacketSource for Gated {
    async fn recv(&mut self) -> io::Result<PacketBuf> {
        self.wait_open().await?;
        self.source.recv().await
    }

    async fn recv_batch(&mut self, batch: &mut PacketBatch) -> io::Result<()> {
        self.wait_open().await?;
        self.source.recv_batch(batch).await
    }

    fn mtu(&self) -> watch::Receiver<u16> {
        self.source.mtu()
    }
}

#[tokio::test]
async fn set_mtu_before_the_engine_applies_to_queued_packets() -> TestResult {
    const INITIAL_MTU: u16 = 1280;
    let a = (
        TransportId::new(1),
        SocketAddr::from(([192, 0, 2, 1], 1000)),
    );
    let b = (
        TransportId::new(2),
        SocketAddr::from(([192, 0, 2, 2], 2000)),
    );
    let (link_a, link_b) = ChannelTransport::pair(1024, a, b);
    let mut node = Node::new(2, b.0, b.1, link_b, Options::default());

    // The host pushes before the configured MTU is known: one packet above the configured
    // MTU, and one above the initial MTU that fits the configured one.
    let (input, mut source, sink) = host_tun(
        INITIAL_MTU,
        HOST_TUN_DEFAULT_CAPACITY,
        Arc::new(|_: &[u8]| true),
    );
    let too_long = Host::packet_to(&node, Family::V6, usize::from(nsplane_e2e::MTU) - 47);
    let fits = Host::packet_to(&node, Family::V4, usize::from(nsplane_e2e::MTU) - 28);
    assert_eq!(too_long.len(), usize::from(nsplane_e2e::MTU) + 1);
    assert!(fits.len() > usize::from(INITIAL_MTU));
    input.push(&too_long)?;
    input.push(&fits)?;
    source.set_mtu(nsplane_e2e::MTU);

    let (open, gate) = watch::channel(false);
    let engine = EngineBuilder::new(Gated { source, open: gate }, sink)
        .private_key(StaticSecret::from([SEED; 32]))
        .transport(link_a)
        .build()?;
    let (_, written) = mpsc::unbounded_channel();
    let host = Host {
        handle: engine.handle(),
        _engine: engine,
        input,
        written,
    };
    assert_eq!(host.handle.mtu().await?, nsplane_e2e::MTU);
    introduce(&host, &node).await?;
    open.send(true)?;

    // The queued packet that fits the new MTU is forwarded, the other one was dropped.
    assert_eq!(node.expect_delivery().await?.1, fits);
    node.expect_no_delivery().await?;
    let next = Host::packet_to(&node, Family::V4, 64);
    host.push(vec![next.clone()]).await?;
    assert_eq!(node.expect_delivery().await?.1, next);
    Ok(())
}
