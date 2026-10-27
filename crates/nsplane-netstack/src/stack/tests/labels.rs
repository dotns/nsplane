//! Ingress labels: the tag of a packet sent into `NetStackSink` attributes it to a lifetime.
//! A lifetime takes the label of its first input, `None` included, and input with another
//! label is dropped and counted, on an ordinary stack and on a transparent one with
//! `Immediate` and `Decide`.

use std::num::NonZeroU64;

use nsplane_packet::reassembly::ReassemblyConfig;
use tokio::io::AsyncWriteExt;

use super::pmtu::too_big;
use super::reassembly::fragments_v4;
use super::*;
use crate::{PendingFlow, TransparentConfig, UdpFlow};

pub(super) const LOCAL: Ipv4Addr = Ipv4Addr::new(10, 9, 0, 1);
pub(super) const CLIENT: Ipv4Addr = Ipv4Addr::new(10, 9, 0, 2);
/// The stack's TCP port.
pub(super) const PORT: u16 = 443;
pub(super) const L1: NonZeroU64 = NonZeroU64::MIN;
pub(super) const L2: NonZeroU64 = NonZeroU64::MIN.saturating_add(1);
pub(super) const L3: NonZeroU64 = NonZeroU64::MIN.saturating_add(2);

const DECIDE: Admission = Admission::Decide {
    timeout: Duration::from_secs(5),
    max_pending: 8,
};

/// The stacks every rule is checked on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Kind {
    /// The stack's own addresses, `Admission::Immediate`.
    Ordinary,
    /// Transparent, `Admission::Immediate`.
    Transparent,
    /// Transparent, `Admission::Decide`.
    Decide,
}

pub(super) const KINDS: [Kind; 3] = [Kind::Ordinary, Kind::Transparent, Kind::Decide];

/// A stack of `kind` at [`LOCAL`], with reassembly.
pub(super) fn stack_config(kind: Kind) -> NetStackConfig {
    let mut config = NetStackConfig::new(vec![(IpAddr::V4(LOCAL), 32)], 1360);
    config.reassembly = Some(ReassemblyConfig::default());
    if kind != Kind::Ordinary {
        config.transparent = Some(TransparentConfig::default());
    }
    if kind == Kind::Decide {
        config.admission = DECIDE;
    }
    config
}

/// Accepts every item of `incoming_pending` (only `Decide` offers any).
pub(super) fn accept_all(handle: &NetStackHandle) {
    let mut pending = handle.incoming_pending();
    tokio::spawn(async move {
        while let Some(item) = next(&mut pending).await {
            item.accept();
        }
    });
}

/// `bytes` as a packet with the tag `label`.
pub(super) fn tagged(bytes: &[u8], label: Option<NonZeroU64>) -> PacketBuf {
    let mut packet = PacketBuf::from_packet(bytes);
    packet.set_tag(label);
    packet
}

/// Sends `bytes` into the stack with the tag `label`.
pub(super) async fn send(
    sink: &NetStackSink,
    bytes: &[u8],
    label: Option<NonZeroU64>,
) -> TestResult {
    sink.send(tagged(bytes, label), PeerId::new(0)).await?;
    Ok(())
}

/// Sends a UDP datagram from `remote` to `local` with `payload` and the tag `label`.
pub(super) async fn datagram(
    sink: &NetStackSink,
    remote: SocketAddr,
    local: SocketAddr,
    payload: &[u8],
    label: Option<NonZeroU64>,
) -> TestResult {
    let packet = build_udp(remote, local, payload).ok_or("build")?;
    send(sink, packet.as_packet(), label).await
}

/// The next flow of `incoming`, waiting for it.
pub(super) async fn flow(
    incoming: &mut (impl Stream<Item = UdpFlow> + Unpin),
) -> Result<UdpFlow, Box<dyn Error>> {
    Ok(timeout(WAIT, next(incoming)).await?.ok_or("no flow")?)
}

/// Whether `incoming` hands nothing out within a short while.
pub(super) async fn quiet<T>(incoming: &mut (impl Stream<Item = T> + Unpin)) -> bool {
    timeout(Duration::from_millis(100), next(incoming))
        .await
        .is_err()
}

/// The next datagram of `flow`, waiting for it.
pub(super) async fn received(flow: &mut UdpFlow) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(timeout(WAIT, flow.recv())
        .await?
        .ok_or("flow ended")?
        .to_vec())
}

/// Waits until `ready` holds for the stack's counters.
pub(super) async fn until_stats(
    handle: &NetStackHandle,
    ready: impl Fn(&NetStackStats) -> bool + Sync,
) -> TestResult {
    timeout(WAIT, async {
        while !ready(&handle.stats()) {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| format!("counters should converge: {:?}", handle.stats()))?;
    Ok(())
}

/// Moves the stack's egress into the client and polls it; returns the client's packets,
/// not sent.
pub(super) fn client_turn(peer: &mut RawPeer) -> Vec<Vec<u8>> {
    while let Some(packet) = peer.source.try_admit() {
        peer.device.inject(packet);
    }
    let now = peer.now();
    peer.iface.poll(now, &mut peer.device, &mut peer.sockets);
    peer.device
        .drain_tx()
        .map(|packet| packet.as_packet().to_vec())
        .collect()
}

/// Shuttles packets both ways once, the client's with the tag `label`.
pub(super) async fn pump_labeled(peer: &mut RawPeer, label: Option<NonZeroU64>) {
    for packet in client_turn(peer) {
        let _ = peer.sink.send(tagged(&packet, label), PeerId::new(0)).await;
    }
    sleep(Duration::from_millis(5)).await;
}

/// Connects a client socket from `port` to the stack's [`PORT`], every client packet with
/// the tag `label`; returns the socket and the stack's connection.
pub(super) async fn connected(
    peer: &mut RawPeer,
    incoming: &mut (impl Stream<Item = TcpConnection> + Unpin),
    port: u16,
    label: Option<NonZeroU64>,
) -> Result<(SocketHandle, TcpConnection), Box<dyn Error>> {
    let socket = peer.connect(LOCAL, PORT, port)?;
    for _ in 0..200 {
        pump_labeled(peer, label).await;
        if let Some(conn) = try_next(incoming) {
            return Ok((socket, conn));
        }
    }
    Err("a connection should be handed out".into())
}

/// The client's packets until it answers the stack's SYN-ACK: the SYN it sent with the tag
/// `label` and its ACK, which is not sent.
async fn syn_and_ack(
    peer: &mut RawPeer,
    port: u16,
    label: Option<NonZeroU64>,
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    peer.connect(LOCAL, PORT, port)?;
    let syn = client_turn(peer).into_iter().next().ok_or("no SYN")?;
    send(&peer.sink, &syn, label).await?;
    for _ in 0..200 {
        sleep(Duration::from_millis(5)).await;
        if let Some(ack) = client_turn(peer).into_iter().next() {
            return Ok((syn, ack));
        }
    }
    Err("the stack should answer the SYN".into())
}

/// Reads what `conn` received, waiting for at least one byte.
async fn read_some(conn: &mut TcpConnection) -> Result<Vec<u8>, Box<dyn Error>> {
    timeout(WAIT, async {
        loop {
            let data = try_read(conn);
            if !data.is_empty() {
                return data;
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| "no bytes".into())
}

// ── TCP ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_connection_takes_the_label_of_its_syn() -> TestResult {
    for kind in KINDS {
        let (handle, mut peer) = RawPeer::start(stack_config(kind), CLIENT, 51);
        accept_all(&handle);
        let mut incoming = handle.incoming_tcp();
        let (socket, mut conn) = connected(&mut peer, &mut incoming, 40_001, Some(L1)).await?;
        assert_eq!(conn.ingress_label(), Some(L1), "{kind:?}");
        peer.socket(socket).send_slice(b"labeled")?;
        pump_labeled(&mut peer, Some(L1)).await;
        assert_eq!(read_some(&mut conn).await?, b"labeled", "{kind:?}");

        let (_, unlabeled) = connected(&mut peer, &mut incoming, 40_002, None).await?;
        assert_eq!(unlabeled.ingress_label(), None, "{kind:?}");
        assert_eq!(handle.stats().label_mismatch, 0, "{kind:?}");
    }
    Ok(())
}

#[tokio::test]
async fn a_handshake_ack_and_a_retransmitted_syn_with_another_label_are_dropped() -> TestResult {
    for kind in KINDS {
        let (handle, mut peer) = RawPeer::start(stack_config(kind), CLIENT, 52);
        accept_all(&handle);
        let mut incoming = handle.incoming_tcp();
        let (syn, ack) = syn_and_ack(&mut peer, 40_010, Some(L1)).await?;

        send(&peer.sink, &ack, Some(L2)).await?;
        until_stats(&handle, |stats| stats.label_mismatch == 1).await?;
        send(&peer.sink, &syn, Some(L2)).await?;
        until_stats(&handle, |stats| stats.label_mismatch == 2).await?;
        send(&peer.sink, &ack, None).await?;
        until_stats(&handle, |stats| stats.label_mismatch == 3).await?;
        assert!(quiet(&mut incoming).await, "{kind:?}: not established");

        // The same label passes: a retransmitted SYN, then the ACK.
        send(&peer.sink, &syn, Some(L1)).await?;
        send(&peer.sink, &ack, Some(L1)).await?;
        let conn = timeout(WAIT, next(&mut incoming))
            .await?
            .ok_or("no connection")?;
        assert_eq!(conn.ingress_label(), Some(L1), "{kind:?}");
        assert_eq!(handle.stats().label_mismatch, 3, "{kind:?}");
    }
    Ok(())
}

#[tokio::test]
async fn established_segments_with_another_label_or_none_are_dropped() -> TestResult {
    for kind in KINDS {
        let (handle, mut peer) = RawPeer::start(stack_config(kind), CLIENT, 53);
        accept_all(&handle);
        let mut incoming = handle.incoming_tcp();
        let (socket, mut conn) = connected(&mut peer, &mut incoming, 40_020, Some(L1)).await?;
        peer.socket(socket).send_slice(b"one")?;
        let segment = client_turn(&mut peer).into_iter().next().ok_or("no data")?;

        send(&peer.sink, &segment, Some(L2)).await?;
        until_stats(&handle, |stats| stats.label_mismatch == 1).await?;
        send(&peer.sink, &segment, None).await?;
        until_stats(&handle, |stats| stats.label_mismatch == 2).await?;
        sleep(Duration::from_millis(20)).await;
        assert!(try_read(&mut conn).is_empty(), "{kind:?}");

        send(&peer.sink, &segment, Some(L1)).await?;
        assert_eq!(read_some(&mut conn).await?, b"one", "{kind:?}");

        // An unlabeled connection takes no labeled segment.
        let (socket, mut unlabeled) = connected(&mut peer, &mut incoming, 40_021, None).await?;
        peer.socket(socket).send_slice(b"two")?;
        let segment = client_turn(&mut peer).into_iter().next().ok_or("no data")?;
        send(&peer.sink, &segment, Some(L1)).await?;
        until_stats(&handle, |stats| stats.label_mismatch == 3).await?;
        send(&peer.sink, &segment, None).await?;
        assert_eq!(read_some(&mut unlabeled).await?, b"two", "{kind:?}");
    }
    Ok(())
}

#[tokio::test]
async fn icmp_errors_unlabeled_apply_and_with_another_label_are_ignored() -> TestResult {
    let router = IpAddr::V4(Ipv4Addr::new(10, 9, 0, 254));
    for kind in KINDS {
        let (handle, mut peer) = RawPeer::start(stack_config(kind), CLIENT, 54);
        accept_all(&handle);
        let mut incoming = handle.incoming_tcp();
        let (_, mut conn) = connected(&mut peer, &mut incoming, 40_030, Some(L1)).await?;
        conn.write_all(&[7; 8 * 1024]).await?;
        // A full-size segment in flight, never delivered to the client.
        let segment = timeout(WAIT, async {
            loop {
                if let Some(packet) = peer.source.try_admit()
                    && packet.len() > 1000
                {
                    return packet;
                }
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        let message = too_big(router, segment.as_packet(), 1000)?;

        send(&peer.sink, message.as_packet(), Some(L2)).await?;
        until_stats(&handle, |stats| stats.label_mismatch == 1).await?;
        // Not applied: the unlabeled message lowers the MSS, which it could not if the
        // first had.
        send(&peer.sink, message.as_packet(), None).await?;
        sleep(Duration::from_millis(20)).await;
        let stats = handle.stats();
        assert_eq!(
            (stats.label_mismatch, stats.icmp_ignored),
            (1, 0),
            "{kind:?}"
        );
        // Applied once: a third, labeled like the connection, has nothing left to lower.
        send(&peer.sink, message.as_packet(), Some(L1)).await?;
        until_stats(&handle, |stats| stats.icmp_ignored == 1).await?;
        assert_eq!(handle.stats().label_mismatch, 1, "{kind:?}");
    }
    Ok(())
}

// ── UDP ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_flow_takes_the_label_of_its_first_datagram() -> TestResult {
    let local = SocketAddr::new(LOCAL.into(), 53);
    let (first, second): (SocketAddr, SocketAddr) =
        ("10.9.0.2:5000".parse()?, "10.9.0.2:5001".parse()?);
    for kind in KINDS {
        let (stack, handle) = NetStack::new(stack_config(kind));
        let (_source, sink) = stack.split();
        accept_all(&handle);
        let mut incoming = handle.incoming_udp();

        datagram(&sink, first, local, b"a", Some(L1)).await?;
        let mut labeled = flow(&mut incoming).await?;
        assert_eq!(labeled.ingress_label(), Some(L1), "{kind:?}");
        assert_eq!(received(&mut labeled).await?, b"a");
        datagram(&sink, first, local, b"b", Some(L2)).await?;
        datagram(&sink, first, local, b"c", None).await?;
        datagram(&sink, first, local, b"d", Some(L1)).await?;
        assert_eq!(received(&mut labeled).await?, b"d", "{kind:?}");
        assert_eq!(handle.stats().label_mismatch, 2, "{kind:?}");

        datagram(&sink, second, local, b"e", None).await?;
        let mut unlabeled = flow(&mut incoming).await?;
        assert_eq!(unlabeled.ingress_label(), None, "{kind:?}");
        assert_eq!(received(&mut unlabeled).await?, b"e");
        datagram(&sink, second, local, b"f", Some(L1)).await?;
        datagram(&sink, second, local, b"g", None).await?;
        assert_eq!(received(&mut unlabeled).await?, b"g", "{kind:?}");
        assert_eq!(handle.stats().label_mismatch, 3, "{kind:?}");
        assert!(quiet(&mut incoming).await, "{kind:?}: no other flow");
    }
    Ok(())
}

#[tokio::test]
async fn held_lifetimes_keep_the_label_of_their_first_input() -> TestResult {
    let (handle, mut peer) = RawPeer::start(stack_config(Kind::Decide), CLIENT, 55);
    let mut pending = handle.incoming_pending();
    let mut incoming_udp = handle.incoming_udp();
    let mut incoming_tcp = handle.incoming_tcp();
    let (remote, local): (SocketAddr, SocketAddr) =
        ("10.9.0.2:5000".parse()?, "192.0.2.7:53".parse()?);

    datagram(&peer.sink, remote, local, b"first", Some(L1)).await?;
    let item: PendingFlow = timeout(WAIT, next(&mut pending)).await?.ok_or("no item")?;
    assert_eq!(item.ingress_label(), Some(L1));
    datagram(&peer.sink, remote, local, b"other", Some(L2)).await?;
    until_stats(&handle, |stats| stats.label_mismatch == 1).await?;
    datagram(&peer.sink, remote, local, b"same", Some(L1)).await?;
    until_stats(&handle, |stats| stats.udp_queue_full == 1).await?;
    item.accept();
    let mut flow = flow(&mut incoming_udp).await?;
    assert_eq!(flow.ingress_label(), Some(L1));
    assert_eq!(received(&mut flow).await?, b"first");

    // A held SYN: a retransmission with another label is dropped and counted, one with
    // the same label absorbed.
    peer.connect(LOCAL, PORT, 40_040)?;
    let syn = client_turn(&mut peer).into_iter().next().ok_or("no SYN")?;
    send(&peer.sink, &syn, Some(L2)).await?;
    let item = timeout(WAIT, next(&mut pending)).await?.ok_or("no item")?;
    assert_eq!(item.ingress_label(), Some(L2));
    send(&peer.sink, &syn, Some(L1)).await?;
    until_stats(&handle, |stats| stats.label_mismatch == 2).await?;
    send(&peer.sink, &syn, Some(L2)).await?;
    sleep(Duration::from_millis(20)).await;
    assert_eq!(handle.stats().label_mismatch, 2);
    item.accept();
    for _ in 0..200 {
        pump_labeled(&mut peer, Some(L2)).await;
        if let Some(conn) = try_next(&mut incoming_tcp) {
            assert_eq!(conn.ingress_label(), Some(L2));
            return Ok(());
        }
    }
    Err("the accepted connection should be handed out".into())
}

// ── Fragments ────────────────────────────────────────────────────────

/// A datagram's fragments and its payload.
pub(super) type Fragmented = (Vec<Vec<u8>>, Vec<u8>);

/// The fragments of a datagram from `remote` to `local` with `len` payload bytes, in
/// three pieces, with identification `id`; and the payload.
pub(super) fn fragmented(
    remote: SocketAddr,
    local: SocketAddr,
    len: usize,
    id: u16,
) -> Result<Fragmented, Box<dyn Error>> {
    let payload: Vec<u8> = (0..len).map(|i| (i % 251).to_le_bytes()[0]).collect();
    let packet = build_udp(remote, local, &payload).ok_or("build")?;
    let chunk = (len + 8).div_ceil(3).next_multiple_of(8);
    let fragments = fragments_v4(packet.as_packet(), chunk, id);
    assert_eq!(fragments.len(), 3);
    Ok((fragments, payload))
}

#[tokio::test]
async fn fragments_with_mixed_labels_are_dropped_and_counted() -> TestResult {
    let local = SocketAddr::new(LOCAL.into(), 53);
    let remote: SocketAddr = "10.9.0.2:5000".parse()?;
    for kind in KINDS {
        let (stack, handle) = NetStack::new(stack_config(kind));
        let (_source, sink) = stack.split();
        accept_all(&handle);
        let mut incoming = handle.incoming_udp();

        // A partial datagram completed after a listener replacement: the middle fragment
        // arrives with the old and the new label.
        let (pieces, _) = fragmented(remote, local, 600, 1)?;
        send(&sink, &pieces[0], Some(L1)).await?;
        send(&sink, &pieces[1], Some(L1)).await?;
        send(&sink, &pieces[1], Some(L2)).await?;
        send(&sink, &pieces[2], Some(L2)).await?;
        until_stats(&handle, |stats| stats.label_mismatch == 1).await?;
        // A tag and none.
        let (pieces, _) = fragmented(remote, local, 600, 2)?;
        send(&sink, &pieces[0], None).await?;
        send(&sink, &pieces[1], Some(L1)).await?;
        send(&sink, &pieces[2], None).await?;
        until_stats(&handle, |stats| stats.label_mismatch == 2).await?;
        assert!(quiet(&mut incoming).await, "{kind:?}: nothing delivered");

        // The same label on every fragment: the datagram keeps it.
        let (pieces, payload) = fragmented(remote, local, 600, 3)?;
        for piece in &pieces {
            send(&sink, piece, Some(L2)).await?;
        }
        let mut flow = flow(&mut incoming).await?;
        assert_eq!(flow.ingress_label(), Some(L2), "{kind:?}");
        assert_eq!(received(&mut flow).await?, payload);
        // A datagram of the flow's tuple with another label, whole or in fragments.
        let (pieces, _) = fragmented(remote, local, 600, 4)?;
        for piece in &pieces {
            send(&sink, piece, Some(L1)).await?;
        }
        until_stats(&handle, |stats| stats.label_mismatch == 3).await?;
        assert_eq!(handle.stats().reassembled, 4, "{kind:?}");
    }
    Ok(())
}

// ── Unlabeled stacks ─────────────────────────────────────────────────

#[tokio::test]
async fn an_unlabeled_stack_counts_no_label() -> TestResult {
    for kind in KINDS {
        let (handle, mut peer) = RawPeer::start(stack_config(kind), CLIENT, 56);
        accept_all(&handle);
        let mut incoming = handle.incoming_tcp();
        let mut incoming_udp = handle.incoming_udp();
        let (socket, mut conn) = connected(&mut peer, &mut incoming, 40_050, None).await?;
        assert_eq!(conn.ingress_label(), None);
        peer.socket(socket).send_slice(b"plain")?;
        pump_labeled(&mut peer, None).await;
        assert_eq!(read_some(&mut conn).await?, b"plain");
        let local = SocketAddr::new(LOCAL.into(), 53);
        datagram(&peer.sink, "10.9.0.2:5000".parse()?, local, b"x", None).await?;
        let mut udp = flow(&mut incoming_udp).await?;
        assert_eq!(udp.ingress_label(), None);
        assert_eq!(received(&mut udp).await?, b"x");
        let stats = handle.stats();
        assert_eq!(
            (stats.label_mismatch, stats.label_revoked),
            (0, 0),
            "{kind:?}"
        );
    }
    Ok(())
}
