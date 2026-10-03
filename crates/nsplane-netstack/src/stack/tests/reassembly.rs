use nsplane_packet::checksum::ipv4_header_checksum;
use nsplane_packet::reassembly::ReassemblyConfig;

use super::*;
use crate::Ownership;

const LOCAL4: Ipv4Addr = Ipv4Addr::new(10, 7, 0, 1);
const LOCAL6: Ipv6Addr = Ipv6Addr::new(0xfd00, 7, 0, 0, 0, 0, 0, 1);
/// Next header of an IPv6 Fragment header.
const IPV6_FRAGMENT: u8 = 44;

/// A dual-stack configuration, with `reassembly`.
fn config(reassembly: Option<ReassemblyConfig>) -> NetStackConfig {
    NetStackConfig {
        reassembly,
        ..NetStackConfig::new(
            vec![(IpAddr::V4(LOCAL4), 32), (IpAddr::V6(LOCAL6), 128)],
            1360,
        )
    }
}

/// `packet` (IPv4, 20-byte header) split into fragments of `chunk` payload bytes (a
/// multiple of 8), with identification `id`.
fn fragments_v4(packet: &[u8], chunk: usize, id: u16) -> Vec<Vec<u8>> {
    let (header, payload) = packet.split_at(20);
    let count = payload.len().div_ceil(chunk);
    payload
        .chunks(chunk)
        .enumerate()
        .map(|(i, data)| {
            let mut fragment = header.to_vec();
            let total = u16::try_from(20 + data.len()).unwrap_or(u16::MAX);
            fragment[2..4].copy_from_slice(&total.to_be_bytes());
            fragment[4..6].copy_from_slice(&id.to_be_bytes());
            let more = if i + 1 < count { 0x2000 } else { 0 };
            let offset = u16::try_from(i * chunk / 8).unwrap_or(0);
            fragment[6..8].copy_from_slice(&(more | offset).to_be_bytes());
            fragment[10..12].fill(0);
            let checksum = ipv4_header_checksum(&fragment);
            fragment[10..12].copy_from_slice(&checksum.to_be_bytes());
            fragment.extend_from_slice(data);
            fragment
        })
        .collect()
}

/// `packet` (IPv6, no extension headers) split into Fragment-header packets of `chunk`
/// payload bytes (a multiple of 8), with identification `id`.
fn fragments_v6(packet: &[u8], chunk: usize, id: u32) -> Vec<Vec<u8>> {
    let (header, payload) = packet.split_at(40);
    let count = payload.len().div_ceil(chunk);
    payload
        .chunks(chunk)
        .enumerate()
        .map(|(i, data)| {
            let mut fragment = header.to_vec();
            let len = u16::try_from(8 + data.len()).unwrap_or(u16::MAX);
            fragment[4..6].copy_from_slice(&len.to_be_bytes());
            fragment[6] = IPV6_FRAGMENT;
            let more = u16::from(i + 1 < count);
            let offset = u16::try_from(i * chunk).unwrap_or(0) | more;
            fragment.extend_from_slice(&[header[6], 0]);
            fragment.extend_from_slice(&offset.to_be_bytes());
            fragment.extend_from_slice(&id.to_be_bytes());
            fragment.extend_from_slice(data);
            fragment
        })
        .collect()
}

/// A UDP packet from `src` to `dst` with `len` payload bytes.
fn datagram(
    src: SocketAddr,
    dst: SocketAddr,
    len: usize,
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    let packet = build_udp(src, dst, &payload).ok_or("build")?;
    Ok((packet.as_packet().to_vec(), payload))
}

async fn send_all(sink: &NetStackSink, packets: impl IntoIterator<Item = Vec<u8>>) -> TestResult {
    for packet in packets {
        sink.send(PacketBuf::from_packet(&packet), PeerId::new(0))
            .await?;
    }
    Ok(())
}

/// Waits until `handle`'s counters satisfy `ready`.
async fn until_stats(
    handle: &NetStackHandle,
    ready: impl Fn(&NetStackStats) -> bool,
) -> TestResult {
    timeout(Duration::from_secs(5), async {
        while !ready(&handle.stats()) {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| format!("counters never matched: {:?}", handle.stats()).into())
}

#[tokio::test]
async fn without_reassembly_fragments_are_dropped() -> TestResult {
    let (stack, handle) = NetStack::new(config(None));
    let (_source, sink) = stack.split();
    let local = SocketAddr::new(LOCAL4.into(), 5353);
    let mut socket = handle.bind_udp(local).await?;
    let (packet, _) = datagram("10.7.0.2:1000".parse()?, local, 100)?;
    let local6 = SocketAddr::new(LOCAL6.into(), 5353);
    let (packet6, _) = datagram("[fd00:7::2]:1000".parse()?, local6, 100)?;
    let mut fragments = fragments_v4(&packet, 64, 1);
    fragments.extend(fragments_v6(&packet6, 64, 1));
    send_all(&sink, fragments).await?;
    until_stats(&handle, |stats| stats.unsupported == 4).await?;
    assert!(
        timeout(Duration::from_millis(100), socket.recv_from())
            .await
            .is_err()
    );
    let stats = handle.stats();
    assert_eq!(
        (
            stats.reassembled,
            stats.reassembly_timeout,
            stats.reassembly_overflow
        ),
        (0, 0, 0)
    );
    Ok(())
}

#[tokio::test]
async fn reassembled_datagrams_reach_a_socket_and_a_flow() -> TestResult {
    let (stack, handle) = NetStack::new(config(Some(ReassemblyConfig::default())));
    let (_source, sink) = stack.split();
    let mut incoming = handle.incoming_udp();
    let local = SocketAddr::new(LOCAL4.into(), 5353);
    let mut socket = handle.bind_udp(local).await?;

    // IPv4 to the bound socket, last fragment first.
    let remote: SocketAddr = "10.7.0.2:1000".parse()?;
    let (packet, payload) = datagram(remote, local, 3000)?;
    let mut fragments = fragments_v4(&packet, 1336, 7);
    fragments.reverse();
    send_all(&sink, fragments).await?;
    let (got, from) = timeout(WAIT, socket.recv_from()).await??;
    assert_eq!((got.as_ref(), from), (&payload[..], remote));

    // IPv6 to a new flow, the first fragment last.
    let remote6: SocketAddr = "[fd00:7::2]:1000".parse()?;
    let local6 = SocketAddr::new(LOCAL6.into(), 4000);
    let (packet6, payload6) = datagram(remote6, local6, 2500)?;
    let mut fragments = fragments_v6(&packet6, 1232, 9);
    fragments.rotate_left(1);
    send_all(&sink, fragments).await?;
    let mut flow = timeout(WAIT, next(&mut incoming)).await?.ok_or("no flow")?;
    assert_eq!((flow.peer_addr(), flow.local_addr()), (remote6, local6));
    let got = timeout(WAIT, flow.recv()).await?.ok_or("flow closed")?;
    assert_eq!(got.as_ref(), &payload6[..]);

    // Unfragmented packets pass as before.
    let (whole, small) = datagram(remote, local, 10)?;
    send_all(&sink, [whole]).await?;
    let (got, _) = timeout(WAIT, socket.recv_from()).await??;
    assert_eq!(got.as_ref(), &small[..]);

    let stats = handle.stats();
    assert_eq!(stats.reassembled, 2);
    assert_eq!(stats.unsupported, 0);
    Ok(())
}

#[tokio::test]
async fn reassembly_counts_timeout_and_overflow() -> TestResult {
    let reassembly = ReassemblyConfig {
        max_datagrams: 1,
        timeout: Duration::from_millis(100),
        max_bytes: 1500,
    };
    let (stack, handle) = NetStack::new(config(Some(reassembly)));
    let (_source, sink) = stack.split();
    let local = SocketAddr::new(LOCAL4.into(), 5353);
    let _socket = handle.bind_udp(local).await?;
    let remote: SocketAddr = "10.7.0.2:1000".parse()?;
    let (packet, _) = datagram(remote, local, 1000)?;

    // One datagram held; a second one is beyond `max_datagrams`.
    let first = fragments_v4(&packet, 512, 1);
    let second = fragments_v4(&packet, 512, 2);
    send_all(&sink, [first[0].clone(), second[0].clone()]).await?;
    until_stats(&handle, |stats| stats.reassembly_overflow == 1).await?;
    // The held one times out, on the driver's own tick.
    until_stats(&handle, |stats| stats.reassembly_timeout == 1).await?;

    // A datagram beyond `max_bytes`.
    let (big, _) = datagram(remote, local, 2000)?;
    send_all(&sink, fragments_v4(&big, 1024, 3)).await?;
    until_stats(&handle, |stats| stats.reassembly_overflow == 2).await?;

    // An overlapping fragment is malformed.
    let mut overlapping = fragments_v4(&packet, 512, 4);
    overlapping[1][6..8].copy_from_slice(&0x2008u16.to_be_bytes());
    send_all(&sink, overlapping).await?;
    until_stats(&handle, |stats| stats.malformed == 1).await?;
    assert_eq!(handle.stats().reassembled, 0);
    Ok(())
}

#[tokio::test]
async fn fragments_are_owned_with_reassembly() -> TestResult {
    let (stack, handle) = NetStack::new(config(Some(ReassemblyConfig::default())));
    let (_source, _sink) = stack.split();
    let local = SocketAddr::new(LOCAL4.into(), 5353);
    let _socket = handle.bind_udp(local).await?;
    let remote: SocketAddr = "10.7.0.2:1000".parse()?;
    let (packet, _) = datagram(remote, local, 1000)?;
    let fragments = fragments_v4(&packet, 512, 1);
    assert_eq!(handle.owns(&fragments[0]), Ownership::Flow, "first, bound");
    assert_eq!(handle.owns(&fragments[1]), Ownership::Listener, "later");
    let (other, _) = datagram(remote, SocketAddr::new(LOCAL4.into(), 9), 1000)?;
    let fragments = fragments_v4(&other, 512, 2);
    assert_eq!(
        handle.owns(&fragments[0]),
        Ownership::Listener,
        "first, new flow"
    );

    let local6 = SocketAddr::new(LOCAL6.into(), 4000);
    let (packet6, _) = datagram("[fd00:7::2]:1000".parse()?, local6, 1000)?;
    let fragments = fragments_v6(&packet6, 512, 1);
    assert_eq!(
        handle.owns(&fragments[0]),
        Ownership::Listener,
        "IPv6 first"
    );
    assert_eq!(
        handle.owns(&fragments[1]),
        Ownership::Listener,
        "IPv6 later"
    );

    // Not to a stack address, or not TCP/UDP: still not the stack's.
    let (elsewhere, _) = datagram(remote, "10.7.0.9:53".parse()?, 1000)?;
    assert_eq!(
        handle.owns(&fragments_v4(&elsewhere, 512, 3)[1]),
        Ownership::None
    );
    let mut icmp = fragments_v4(&packet, 512, 5).remove(1);
    icmp[9] = protocol::ICMP;
    assert_eq!(handle.owns(&icmp), Ownership::None);
    Ok(())
}
