//! Ingress labels between two engines over an in-memory channel transport whose local sides
//! are netstacks. The server's sink labels every packet the engine delivers with the
//! current incarnation of its listeners, as a consumer that classifies its input on the
//! sink side does. On a replacement the server switches the label first and then revokes the
//! old incarnation's label: input of the old connection and flow with the new label is
//! dropped and counted, the revoke retires both (their handles fail), the old flow's tuple
//! opens a fresh lifetime under the new label, and a new connection echoes intact under load.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroU64;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use nsplane::x25519::StaticSecret;
use nsplane::{ChannelTransport, EngineBuilder, PacketSink};
use nsplane_e2e::{
    Family, MTU, QUIET, StackNode, TRANSFER, TestResult, WAIT, next_within, payload,
};
use nsplane_netstack::{NetStack, NetStackConfig, NetStackSink, RetirementOutcome};
use nsplane_packet::{Ecn, PacketBuf, Path, PeerId, TransportId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::{sleep, timeout};

/// Bytes the new connection sends and gets echoed back.
const BULK: usize = 1 << 20;

/// The server's sink: labels each packet with the current incarnation.
struct Labeler {
    inner: NetStackSink,
    current: Arc<AtomicU64>,
}

impl PacketSink for Labeler {
    async fn send(&self, mut packet: PacketBuf, from: PeerId) -> io::Result<()> {
        packet.set_tag(NonZeroU64::new(self.current.load(Ordering::SeqCst)));
        self.inner.send(packet, from).await
    }
}

/// A client node (seed 1) and a server node (seed 2) whose sink labels its input with the
/// returned incarnation, linked by a channel transport pair and introduced to each other.
async fn pair() -> TestResult<(StackNode, StackNode, Arc<AtomicU64>)> {
    let ends = (
        (
            TransportId::new(1),
            SocketAddr::from(([192, 0, 2, 1], 1000)),
        ),
        (
            TransportId::new(2),
            SocketAddr::from(([192, 0, 2, 2], 2000)),
        ),
    );
    let (link_a, link_b) = ChannelTransport::pair(1024, ends.0, ends.1);
    let a = StackNode::new(1, ends.0.0, ends.0.1, link_a, MTU)?;
    let (ip4, ip6) = (
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
    );
    let config = NetStackConfig::new(vec![(IpAddr::V4(ip4), 32), (IpAddr::V6(ip6), 128)], MTU);
    let (stack, handle) = NetStack::new(config);
    let (source, sink) = stack.split();
    let current = Arc::new(AtomicU64::new(1));
    let sink = Labeler {
        inner: sink,
        current: Arc::clone(&current),
    };
    let engine = EngineBuilder::new(source, sink)
        .private_key(StaticSecret::from([2; 32]))
        .transport(link_b)
        .build()?;
    let b = StackNode {
        handle: engine.handle(),
        engine,
        stack: handle,
        secret: StaticSecret::from([2; 32]),
        ip4,
        ip6,
        path: Path {
            transport: ends.1.0,
            addr: ends.1.1,
            ecn: Ecn::NotEct,
        },
    };
    a.handle
        .add_or_update_peer(b.as_peer(a.path.transport))
        .await?;
    b.handle
        .add_or_update_peer(a.as_peer(b.path.transport))
        .await?;
    Ok((a, b, current))
}

/// Waits until the server's `label_mismatch` reaches `count`.
async fn mismatches(b: &StackNode, count: u64) -> TestResult {
    timeout(WAIT, async {
        while b.stack.stats().label_mismatch < count {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| format!("label_mismatch should reach {count}: {:?}", b.stack.stats()))?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replaced_incarnation_retires_its_lifetimes_and_the_new_one_takes_over() -> TestResult {
    let (a, b, current) = pair().await?;
    let (old_label, new_label) = (NonZeroU64::MIN, NonZeroU64::MIN.saturating_add(1));
    let mut incoming = b.stack.incoming_tcp();
    let mut flows = b.stack.incoming_udp();
    let target = b.socket_addr(Family::V4, 80);

    // Incarnation 1: a connection and a flow.
    let mut old_client = timeout(TRANSFER, a.stack.connect_tcp(target)).await??;
    let mut old = next_within(&mut incoming, WAIT).await?;
    assert_eq!(old.ingress_label(), Some(old_label));
    old_client.write_all(b"first").await?;
    let mut buf = [0; 16];
    let n = timeout(WAIT, old.read(&mut buf)).await??;
    assert_eq!(&buf[..n], b"first");
    let socket = a.stack.connect_udp(b.socket_addr(Family::V4, 53)).await?;
    socket.send(b"one").await?;
    let mut old_flow = next_within(&mut flows, WAIT).await?;
    assert_eq!(old_flow.ingress_label(), Some(old_label));
    assert_eq!(
        timeout(WAIT, old_flow.recv()).await?.as_deref(),
        Some(&b"one"[..])
    );

    // The replacement labels the input from now on: the old lifetimes take none of it.
    current.store(new_label.get(), Ordering::SeqCst);
    socket.send(b"between").await?;
    mismatches(&b, 1).await?;
    old_client.write_all(b"between").await?;
    mismatches(&b, 2).await?;
    assert!(timeout(QUIET, old.read(&mut buf)).await.is_err());

    // Then the old incarnation is revoked.
    let outcome = timeout(WAIT, b.stack.revoke_label(old_label).wait()).await?;
    assert_eq!(outcome, RetirementOutcome::Retired);
    assert!(old.control().is_revoked());
    let error = old.read(&mut buf).await.err().ok_or("reads must fail")?;
    assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    assert!(timeout(WAIT, old_flow.recv()).await?.is_none());

    // The old flow's tuple is a fresh lifetime with the new label.
    socket.send(b"two").await?;
    let mut fresh = next_within(&mut flows, WAIT).await?;
    assert_eq!(fresh.ingress_label(), Some(new_label));
    assert_eq!(
        timeout(WAIT, fresh.recv()).await?.as_deref(),
        Some(&b"two"[..])
    );

    // A new connection of the new incarnation echoes intact.
    let client = timeout(TRANSFER, a.stack.connect_tcp(target)).await??;
    let server = next_within(&mut incoming, WAIT).await?;
    assert_eq!(server.ingress_label(), Some(new_label));
    tokio::spawn(async move {
        let (mut reader, mut writer) = tokio::io::split(server);
        tokio::io::copy(&mut reader, &mut writer).await?;
        writer.shutdown().await
    });
    let data = payload(BULK);
    let (mut reader, mut writer) = tokio::io::split(client);
    let sent = data.clone();
    let writer = tokio::spawn(async move {
        writer.write_all(&sent).await?;
        writer.shutdown().await
    });
    let mut echoed = Vec::with_capacity(BULK);
    timeout(TRANSFER, reader.read_to_end(&mut echoed)).await??;
    writer.await??;
    assert!(echoed == data, "the echo must come back intact");
    assert_eq!(b.stack.stats().label_revoked, 0);
    Ok(())
}
