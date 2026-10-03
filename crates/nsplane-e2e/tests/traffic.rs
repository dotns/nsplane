//! Per-transport traffic counters and the engine status snapshot: every datagram one engine
//! hands to a transport is counted on its transport and arrives on the other engine's, the
//! per-transport bytes match the per-peer wire bytes, the counters survive
//! `replace_transport` and leave with `remove_transport`, failed sends are counted on the
//! transport that failed them, and `status` agrees with the single calls.

use std::future::ready;
use std::io;
use std::time::Duration;

use nsplane::{
    ChannelTransport, DROP_TRANSPORT_SEND_ERROR, EngineStatus, PacketBuf, Path, Transport,
    TransportId, TransportStats,
};
use nsplane_e2e::{Family, Node, Options, TestResult, channel_pair, exchange, introduce, transfer};
use tokio::time::sleep;

/// How long [`until`] polls.
const POLL: Duration = Duration::from_secs(5);

/// `node`'s counters of transport `id`.
async fn transport<T: Transport>(node: &Node<T>, id: TransportId) -> TestResult<TransportStats> {
    let stats = node.handle.transport_stats().await?;
    stats
        .into_iter()
        .find(|s| s.id == id)
        .ok_or_else(|| format!("no stats for transport {}", id.get()).into())
}

/// Polls `check` until it holds, for at most [`POLL`]; the transport tasks count after the
/// datagrams moved, so the counters settle shortly after the traffic.
async fn until<F, Fut>(mut check: F) -> TestResult
where
    F: FnMut() -> Fut,
    Fut: Future<Output = TestResult<Option<String>>>,
{
    let step = Duration::from_millis(10);
    let mut waited = Duration::ZERO;
    loop {
        let Some(mismatch) = check().await? else {
            return Ok(());
        };
        if waited >= POLL {
            return Err(format!("{mismatch} after {POLL:?}").into());
        }
        sleep(step).await;
        waited += step;
    }
}

/// Checks that every datagram `a` sent arrived at `b` and the other way around, and that the
/// bytes match each side's per-peer wire counters (no cookie replies here).
async fn settled(
    a: &Node<ChannelTransport>,
    b: &Node<ChannelTransport>,
) -> TestResult<Option<String>> {
    let (ta, tb) = (
        transport(a, a.path.transport).await?,
        transport(b, b.path.transport).await?,
    );
    let pa = a
        .handle
        .peer_stats(a.peer_of(b).await?)
        .await?
        .ok_or("peer")?;
    let pb = b
        .handle
        .peer_stats(b.peer_of(a).await?)
        .await?
        .ok_or("peer")?;
    let ok = ta.tx_datagrams == tb.rx_datagrams
        && tb.tx_datagrams == ta.rx_datagrams
        && ta.tx_bytes == tb.rx_bytes
        && tb.tx_bytes == ta.rx_bytes
        && ta.tx_bytes == pa.tx
        && ta.rx_bytes == pa.rx
        && tb.tx_bytes == pb.tx
        && tb.rx_bytes == pb.rx
        && ta.tx_failed == 0
        && tb.tx_failed == 0;
    Ok((!ok).then(|| {
        format!(
            "a {ta:?} peer tx {} rx {}, b {tb:?} peer tx {} rx {}",
            pa.tx, pa.rx, pb.tx, pb.rx
        )
    }))
}

#[tokio::test]
async fn transports_count_what_peers_send_and_receive() -> TestResult {
    let (mut a, mut b) = channel_pair(Options::default());
    let before = transport(&a, a.path.transport).await?;
    assert_eq!(
        (
            before.rx_datagrams,
            before.rx_bytes,
            before.tx_datagrams,
            before.tx_bytes
        ),
        (0, 0, 0, 0)
    );
    introduce(&a, &b, None).await?;
    exchange(&mut a, &mut b).await?;
    for len in [64, 1300] {
        transfer(&a, &mut b, Family::V4, len).await?;
        transfer(&b, &mut a, Family::V6, len).await?;
    }
    until(|| settled(&a, &b)).await?;
    let stats = transport(&a, a.path.transport).await?;
    // Handshake, at least four data datagrams each way.
    assert!(
        stats.tx_datagrams >= 5 && stats.rx_datagrams >= 5,
        "{stats:?}"
    );
    Ok(())
}

#[tokio::test]
async fn counters_survive_replace_and_leave_with_remove() -> TestResult {
    let (mut a, mut b) = channel_pair(Options::default());
    introduce(&a, &b, None).await?;
    exchange(&mut a, &mut b).await?;
    until(|| settled(&a, &b)).await?;
    let id = a.path.transport;
    let before = transport(&a, id).await?;

    // A replacement under the same id that reaches `b` too: `a`'s end of a fresh link, with
    // `b`'s end added to `b` as a second transport at the same address.
    let other = TransportId::new(9);
    let (new_a, new_b) = ChannelTransport::pair(64, (id, a.path.addr), (other, b.path.addr));
    a.handle.replace_transport(new_a).await?;
    b.handle.add_transport(new_b).await?;
    b.handle
        .set_path(
            a.public(),
            Path {
                transport: other,
                ..a.path
            },
        )
        .await?;
    transfer(&a, &mut b, Family::V4, 200).await?;
    transfer(&b, &mut a, Family::V4, 200).await?;
    until(|| async {
        let now = transport(&a, id).await?;
        let ok = now.tx_datagrams > before.tx_datagrams && now.rx_datagrams > before.rx_datagrams;
        Ok((!ok).then(|| format!("{now:?} not past {before:?}")))
    })
    .await?;

    a.handle.remove_transport(id).await?;
    let ids: Vec<_> = a
        .handle
        .transport_stats()
        .await?
        .iter()
        .map(|s| s.id)
        .collect();
    assert!(!ids.contains(&id), "{ids:?}");
    Ok(())
}

/// A transport that receives from `T` and fails every send.
struct Failing<T>(T);

impl<T: Transport> Transport for Failing<T> {
    fn id(&self) -> TransportId {
        self.0.id()
    }

    async fn recv(&self, buf: &mut PacketBuf) -> io::Result<(usize, Path)> {
        self.0.recv(buf).await
    }

    fn send(&self, _datagram: &[u8], _to: &Path) -> impl Future<Output = io::Result<()>> + Send {
        ready(Err(io::ErrorKind::ConnectionRefused.into()))
    }
}

#[tokio::test]
async fn failed_sends_are_counted_on_their_transport() -> TestResult {
    let (a, b) = channel_pair(Options::default());
    let id = a.path.transport;
    let (link, _far) =
        ChannelTransport::pair(64, (id, a.path.addr), (b.path.transport, b.path.addr));
    a.handle.replace_transport(Failing(link)).await?;
    introduce(&a, &b, None).await?;
    // The first packet to `b` starts a handshake, whose initiation fails to send.
    a.send(&a.packet_to(&b, Family::V4, &[0; 32])).await?;
    until(|| async {
        let stats = transport(&a, id).await?;
        let drops = a.drops(DROP_TRANSPORT_SEND_ERROR).await?;
        let ok = stats.tx_failed >= 1
            && stats.tx_failed == stats.tx_datagrams
            && stats.tx_failed == drops;
        Ok((!ok).then(|| format!("{stats:?}, {drops} send errors")))
    })
    .await
}

#[tokio::test]
async fn status_agrees_with_the_single_calls() -> TestResult {
    let (mut a, mut b) = channel_pair(Options::default());
    introduce(&a, &b, None).await?;
    exchange(&mut a, &mut b).await?;
    until(|| settled(&a, &b)).await?;
    // Stop the timers from adding traffic between the calls.
    a.handle.suspend().await?;
    b.handle.suspend().await?;

    let status: EngineStatus = a.handle.status().await?;
    assert_eq!(status.public_key, Some(a.public()));
    assert_eq!(status.mtu, a.handle.mtu().await?);
    assert!(status.suspended);
    assert_eq!(status.peers, a.handle.peers().await?);
    assert_eq!(status.transports, a.handle.transport_stats().await?);
    assert_eq!(status.drops, a.handle.drop_counters().await?);
    assert_eq!(status.fragments, a.handle.fragment_stats().await?);
    assert_eq!(
        status.queues.local.capacity,
        a.handle.queue_stats().await?.local.capacity
    );
    Ok(())
}
