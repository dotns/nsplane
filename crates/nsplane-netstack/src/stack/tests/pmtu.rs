//! ICMP Fragmentation Needed and `ICMPv6` Packet Too Big for the stack's own TCP.

use tokio::io::AsyncWriteExt;

use super::ownership::ip;
use super::*;

/// The stack's MTU in these tests, and the `RawPeer` device's.
const MTU: usize = 1360;
const SERVER_PORT: u16 = 80;
const CLIENT_PORT: u16 = 49_300;
/// Bytes the stack sends per transfer.
const BULK: usize = 32 * 1024;

/// A stack at `server` and a raw client at `client` connected to it: the stack's handle,
/// the peer, the client socket and the stack's side of the connection.
async fn connected(
    server: IpAddr,
    client: IpAddr,
) -> Result<(NetStackHandle, RawPeer, SocketHandle, TcpConnection), Box<dyn Error>> {
    let prefix = if server.is_ipv4() { 32 } else { 128 };
    let config = NetStackConfig::new(vec![(server, prefix)], 1360);
    let (handle, mut peer) = RawPeer::start_at(config, client, 11);
    let mut incoming = handle.incoming_tcp();
    let socket = peer.connect(server, SERVER_PORT, CLIENT_PORT)?;
    for _ in 0..40 {
        peer.pump(2).await;
        if let Some(conn) = try_next(&mut incoming) {
            return Ok((handle, peer, socket, conn));
        }
    }
    Err("TCP handshake should complete".into())
}

/// A Fragmentation Needed (IPv4) or Packet Too Big (IPv6) from `router` to `dst` reporting
/// `mtu` and quoting `quoted`. Checksums stay 0: the stack does not check them.
fn too_big_quoting(router: IpAddr, dst: IpAddr, quoted: &[u8], mtu: u32) -> PacketBuf {
    let (proto, mut message) = match router {
        IpAddr::V4(_) => {
            let [.., hi, lo] = mtu.to_be_bytes();
            (protocol::ICMP, vec![3, 4, 0, 0, 0, 0, hi, lo])
        }
        IpAddr::V6(_) => {
            let mut message = vec![2, 0, 0, 0];
            message.extend_from_slice(&mtu.to_be_bytes());
            (protocol::ICMPV6, message)
        }
    };
    message.extend_from_slice(quoted);
    PacketBuf::from_packet(&ip(router, dst, proto, &message))
}

/// [`too_big_quoting`] `packet` to its source with the quote a router sends: the IP header
/// and 8 bytes (IPv4, RFC 792), or as much as fits a 1280-byte message (IPv6, RFC 4443).
fn too_big(router: IpAddr, packet: &[u8], mtu: u32) -> Result<PacketBuf, Box<dyn Error>> {
    let src = IpPacket::parse(packet)
        .map_err(|_| "not an IP packet")?
        .src();
    let quote = if src.is_ipv4() {
        usize::from(packet[0] & 0xf) * 4 + 8
    } else {
        1280 - 48
    };
    Ok(too_big_quoting(
        router,
        src,
        &packet[..quote.min(packet.len())],
        mtu,
    ))
}

/// What [`pump_through`] passed and dropped.
#[derive(Default)]
struct Hop {
    largest: usize,
    dropped: u64,
    received: usize,
}

/// One tick of [`RawPeer::pump_once`] through a hop that drops every stack packet above
/// `limit` bytes and answers it with a too-big message from `router`; the client reads
/// what it received.
async fn pump_through(
    peer: &mut RawPeer,
    client: SocketHandle,
    router: IpAddr,
    limit: usize,
    hop: &mut Hop,
) -> TestResult {
    while let Ok(packet) = peer.source.rx.try_recv() {
        let len = packet.as_packet().len();
        if len > limit {
            hop.dropped += 1;
            let reply = too_big(router, packet.as_packet(), u32::try_from(limit)?)?;
            peer.sink.send(reply, PeerId::new(0)).await?;
        } else {
            hop.largest = hop.largest.max(len);
            peer.device.inject(packet);
        }
    }
    let now = peer.now();
    peer.iface.poll(now, &mut peer.device, &mut peer.sockets);
    let packets: Vec<PacketBuf> = peer.device.drain_tx().collect();
    for packet in packets {
        peer.sink.send(packet, PeerId::new(0)).await?;
    }
    while let Ok(n) = peer.socket(client).recv(|data| (data.len(), data.len())) {
        if n == 0 {
            break;
        }
        hop.received += n;
    }
    sleep(Duration::from_millis(5)).await;
    Ok(())
}

/// Pumps through a hop of `limit` until the client received `len` bytes, for at most five
/// seconds.
async fn transfer_through(
    peer: &mut RawPeer,
    client: SocketHandle,
    router: IpAddr,
    limit: usize,
    len: usize,
) -> Result<Hop, Box<dyn Error>> {
    let mut hop = Hop::default();
    timeout(Duration::from_secs(5), async {
        while hop.received < len {
            pump_through(peer, client, router, limit, &mut hop).await?;
        }
        TestResult::Ok(())
    })
    .await
    .map_err(|_| format!("{} of {len} bytes through a {limit}-byte hop", hop.received))??;
    Ok(hop)
}

/// Waits until `handle`'s counters satisfy `ready`.
async fn until_stats(
    handle: &NetStackHandle,
    ready: impl Fn(NetStackStats) -> bool + Send + Sync,
) -> TestResult {
    timeout(Duration::from_secs(5), async {
        while !ready(handle.stats()) {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| format!("counters did not converge: {:?}", handle.stats()))?;
    Ok(())
}

/// A bulk transfer from the stack through a hop of `limit` bytes that answers larger
/// packets with a too-big message completes, in segments that fit the hop.
async fn bulk_through_a_smaller_hop(
    server: IpAddr,
    client: IpAddr,
    router: IpAddr,
    limit: usize,
) -> TestResult {
    let (handle, mut peer, socket, mut conn) = connected(server, client).await?;
    conn.write_all(&vec![7; BULK]).await?;
    let hop = transfer_through(&mut peer, socket, router, limit, BULK).await?;
    assert_eq!(hop.received, BULK);
    assert!(hop.dropped > 0, "the first window is above the hop's MTU");
    assert_eq!(hop.largest, limit, "segments of the lowered MSS");
    // The first message lowered the MSS; the others, for segments sent before it took
    // effect, report no lower MTU.
    until_stats(&handle, |stats| stats.icmp_ignored == hop.dropped - 1).await?;
    assert_eq!(handle.stats().unsupported, 0);
    Ok(())
}

#[tokio::test]
async fn fragmentation_needed_lowers_the_connection_mss() -> TestResult {
    bulk_through_a_smaller_hop(
        "10.9.7.1".parse()?,
        "10.9.7.2".parse()?,
        "10.9.7.254".parse()?,
        1200,
    )
    .await
}

#[tokio::test]
async fn packet_too_big_lowers_the_connection_mss() -> TestResult {
    bulk_through_a_smaller_hop(
        "fd00:9:7::1".parse()?,
        "fd00:9:7::2".parse()?,
        "fd00:9:7::fe".parse()?,
        1280,
    )
    .await
}

/// Takes the stack's first full-size segment off the wire.
async fn held_segment(peer: &mut RawPeer) -> Result<Vec<u8>, Box<dyn Error>> {
    timeout(WAIT, async {
        loop {
            let packet = peer.source.rx.recv().await.ok_or("stack stopped")?;
            if packet.as_packet().len() == MTU {
                return Ok(packet.as_packet().to_vec());
            }
        }
    })
    .await?
}

#[tokio::test]
async fn invalid_fragmentation_needed_is_ignored_and_counted() -> TestResult {
    let (server, client): (IpAddr, IpAddr) = ("10.9.8.1".parse()?, "10.9.8.2".parse()?);
    let router: IpAddr = "10.9.8.254".parse()?;
    let (handle, mut peer, socket, mut conn) = connected(server, client).await?;
    conn.write_all(&vec![7; BULK]).await?;
    let segment = held_segment(&mut peer).await?;
    let quote = &segment[..28];
    let with = |at: usize, bytes: &[u8]| {
        let mut quote = quote.to_vec();
        quote[at..at + bytes.len()].copy_from_slice(bytes);
        quote
    };
    let seq = u32::from_be_bytes([quote[24], quote[25], quote[26], quote[27]]);
    let ignored = [
        // Another remote port, an unknown remote, a source not the stack's.
        with(22, &(CLIENT_PORT + 1).to_be_bytes()),
        with(16, &[10, 9, 8, 3]),
        with(12, &[10, 9, 8, 9]),
        // A sequence number outside SND.UNA..SND.NXT.
        with(24, &seq.wrapping_add(1 << 20).to_be_bytes()),
        with(24, &seq.wrapping_sub(1).to_be_bytes()),
        // Malformed: no sequence number, not TCP, an IPv6 quote.
        quote[..24].to_vec(),
        with(9, &[protocol::UDP]),
        with(0, &[0x60]),
    ];
    for quoted in &ignored {
        let message = too_big_quoting(router, server, quoted, 1200);
        peer.sink.send(message, PeerId::new(0)).await?;
    }
    // MTU 0 (no plateau guess), below 576, not below the stack's MTU.
    for mtu in [0, 575, 1360, 1500, 65_535] {
        let message = too_big_quoting(router, server, quote, mtu);
        peer.sink.send(message, PeerId::new(0)).await?;
    }
    // Other ICMP keeps today's count: host unreachable and an echo request.
    let mut unreachable = too_big_quoting(router, server, quote, 1200);
    unreachable.as_packet_mut()[21] = 1;
    peer.sink.send(unreachable, PeerId::new(0)).await?;
    let echo = ip(router, server, protocol::ICMP, &[8, 0, 0, 0, 0, 1, 0, 1]);
    peer.sink
        .send(PacketBuf::from_packet(&echo), PeerId::new(0))
        .await?;

    let expected = u64::try_from(ignored.len())? + 5;
    until_stats(&handle, |stats| {
        stats.icmp_ignored == expected && stats.unsupported == 2
    })
    .await?;
    // The MSS is unchanged: the rest of the transfer still uses full-size segments.
    peer.device.inject(PacketBuf::from_packet(&segment));
    let hop = transfer_through(&mut peer, socket, router, MTU, BULK).await?;
    assert_eq!(hop.largest, MTU);
    assert_eq!(hop.dropped, 0);
    Ok(())
}

#[tokio::test]
async fn invalid_packet_too_big_is_ignored_and_counted() -> TestResult {
    let (server, client): (IpAddr, IpAddr) = ("fd00:9:8::1".parse()?, "fd00:9:8::2".parse()?);
    let router: IpAddr = "fd00:9:8::fe".parse()?;
    let (handle, mut peer, socket, mut conn) = connected(server, client).await?;
    conn.write_all(&vec![7; BULK]).await?;
    let segment = held_segment(&mut peer).await?;
    // Below 1280, not below the stack's MTU, and an IPv4 quote.
    for mtu in [0, 1279, 1360, 1500] {
        peer.sink
            .send(too_big(router, &segment, mtu)?, PeerId::new(0))
            .await?;
    }
    let mut v4_quote = segment[..48].to_vec();
    v4_quote[0] = 0x45;
    let message = too_big_quoting(router, server, &v4_quote, 1280);
    peer.sink.send(message, PeerId::new(0)).await?;
    until_stats(&handle, |stats| stats.icmp_ignored == 5).await?;

    peer.device.inject(PacketBuf::from_packet(&segment));
    let hop = transfer_through(&mut peer, socket, router, MTU, BULK).await?;
    assert_eq!(hop.largest, MTU);
    assert_eq!(handle.stats().unsupported, 0);
    Ok(())
}
