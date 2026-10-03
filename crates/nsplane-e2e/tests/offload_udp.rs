//! Two engines over [`UdpTransport`]s on the loopback interface, with segmentation offload
//! on and off: a bulk transfer of several flows (IPv4 and IPv6 packets around the MTU) in
//! both directions at once arrives intact and in order per flow, and the engines' counters
//! agree with each other and with what was sent. Bursts of [`WINDOW`] packets each way rely
//! on the transport's default socket buffers.
//!
//! As root (`CAP_NET_ADMIN`), [`fragmentation_follows_bind_time_offload`] lowers the MTU of
//! `lo`: a datagram above it leaves in fragments and arrives whole from a transport bound
//! without offload, and fails to send with `EMSGSIZE` from one bound with offload. Run it
//! alone (`-- --ignored`), as the lower MTU affects every other test in the network
//! namespace.

use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use nsplane::{TransportId, UdpTransport};
use nsplane_e2e::{Family, MTU, Node, Options, TestResult, WAIT, introduce, payload, transfer};
use nsplane_packet::{PacketBuf, PeerId};
use tokio::time::{Instant, sleep, timeout};

/// Flows per direction; even flows carry IPv4 packets, odd flows IPv6 packets.
const FLOWS: usize = 4;
/// Packets per direction, spread round robin over the flows.
const PACKETS: usize = 4096;
/// Packets per direction in flight at once: more than Linux's default 208 KiB receive
/// buffer holds, well within the transport's default socket buffers, so loopback drops
/// nothing.
const WINDOW: usize = 512;
/// IPv4 and IPv6 header plus UDP header of the packets.
const V4_HEADERS: usize = 28;
const V6_HEADERS: usize = 48;

fn node(seed: u8, ip: IpAddr, offload: bool) -> io::Result<Node<UdpTransport>> {
    let id = TransportId::new(u16::from(seed));
    let transport = UdpTransport::bind(id, SocketAddr::new(ip, 0))?;
    transport.set_offload(offload)?;
    assert_eq!(transport.offload(), offload);
    let (recv, send) = (transport.recv_buffer_size()?, transport.send_buffer_size()?);
    writeln!(io::stderr(), "socket buffers: receive {recv}, send {send}")?;
    let addr = transport.local_addr();
    Ok(Node::new(seed, id, addr, transport, Options::default()))
}

/// Fails if `node` counted any drop.
async fn expect_no_drops(node: &Node<UdpTransport>) -> TestResult {
    let counters = node.handle.drop_counters().await?;
    let dropped: Vec<_> = counters.iter().filter(|(_, count)| **count > 0).collect();
    if !dropped.is_empty() {
        return Err(format!("drops counted: {dropped:?}").into());
    }
    Ok(())
}

/// Packet `seq` from `from` to `to`: its flow, and the packet. Most packets fill the MTU, so
/// runs of equal datagrams form; every seventh is shorter.
fn packet(from: &Node<UdpTransport>, to: &Node<UdpTransport>, seq: usize) -> (usize, Vec<u8>) {
    let flow = seq % FLOWS;
    let (family, headers) = if flow.is_multiple_of(2) {
        (Family::V4, V4_HEADERS)
    } else {
        (Family::V6, V6_HEADERS)
    };
    let full = usize::from(MTU) - headers;
    let len = if seq % 7 == 6 {
        full - 1 - seq % 600
    } else {
        full
    };
    let mut data = payload(len);
    data[0] = u8::try_from(flow).unwrap_or(u8::MAX);
    data[1..9].copy_from_slice(&(seq as u64).to_be_bytes());
    (flow, from.packet_to(to, family, &data))
}

/// The packets `from` sends to `to`, by flow, in order.
fn bulk(from: &Node<UdpTransport>, to: &Node<UdpTransport>) -> Vec<Vec<u8>> {
    (0..PACKETS).map(|seq| packet(from, to, seq).1).collect()
}

/// Receives `count` packets at `node`, all from `peer`, and appends them to their flows.
async fn collect(
    node: &mut Node<UdpTransport>,
    peer: PeerId,
    count: usize,
    flows: &mut [Vec<Vec<u8>>],
) -> TestResult {
    for _ in 0..count {
        let (from, packet) = match timeout(WAIT, node.delivered.recv()).await {
            Ok(Some((from, packet))) => (from, packet.as_packet().to_vec()),
            Ok(None) => return Err("sink closed".into()),
            Err(_) => return Err(format!("packet missing after {WAIT:?}").into()),
        };
        if from != peer {
            return Err(format!("packet attributed to {from:?}").into());
        }
        // The flow number is the first payload byte, after the IP and UDP headers.
        let headers = if packet[0] >> 4 == 4 {
            V4_HEADERS
        } else {
            V6_HEADERS
        };
        let flow = usize::from(packet[headers]);
        flows
            .get_mut(flow)
            .ok_or_else(|| format!("unknown flow {flow}"))?
            .push(packet);
    }
    Ok(())
}

/// Moves [`PACKETS`] packets each way between `a` and `b` at once, [`WINDOW`] at a time, and
/// checks every flow and the counters.
async fn bulk_transfer(mut a: Node<UdpTransport>, mut b: Node<UdpTransport>) -> TestResult {
    introduce(&a, &b, None).await?;
    // The handshake first, so no packet waits for it.
    transfer(&a, &mut b, Family::V4, 64).await?;
    transfer(&b, &mut a, Family::V4, 64).await?;
    let (a_b, b_a) = (a.peer_of(&b).await?, b.peer_of(&a).await?);
    let warm = [
        a.handle
            .peer_stats(a_b)
            .await?
            .ok_or("unknown peer")?
            .data_tx,
        b.handle
            .peer_stats(b_a)
            .await?
            .ok_or("unknown peer")?
            .data_tx,
    ];
    let (to_b, to_a) = (bulk(&a, &b), bulk(&b, &a));
    let mut at_b = vec![Vec::new(); FLOWS];
    let mut at_a = vec![Vec::new(); FLOWS];
    for start in (0..PACKETS).step_by(WINDOW) {
        let end = (start + WINDOW).min(PACKETS);
        for seq in start..end {
            a.local.send(PacketBuf::from_packet(&to_b[seq])).await?;
            b.local.send(PacketBuf::from_packet(&to_a[seq])).await?;
        }
        collect(&mut b, b_a, end - start, &mut at_b).await?;
        collect(&mut a, a_b, end - start, &mut at_a).await?;
    }
    for (sent, flows) in [(&to_b, &at_b), (&to_a, &at_a)] {
        for (flow, received) in flows.iter().enumerate() {
            let expected: Vec<_> = sent.iter().skip(flow).step_by(FLOWS).collect();
            if received.len() != expected.len() {
                return Err(format!(
                    "flow {flow}: {} of {} packets",
                    received.len(),
                    expected.len()
                )
                .into());
            }
            if let Some(at) = (0..expected.len()).find(|&at| received[at] != *expected[at]) {
                return Err(
                    format!("flow {flow}: packet {at} changed, lost or out of order").into(),
                );
            }
        }
    }

    // Payload counters grew by what was sent; wire counters match each other once nothing
    // is in flight.
    for (from, peer, to, back, sent, warm) in [
        (&a, a_b, &b, b_a, &to_b, warm[0]),
        (&b, b_a, &a, a_b, &to_a, warm[1]),
    ] {
        let bytes = warm + sent.iter().map(|packet| packet.len() as u64).sum::<u64>();
        let deadline = Instant::now() + WAIT;
        loop {
            let out = from.handle.peer_stats(peer).await?.ok_or("unknown peer")?;
            let r#in = to.handle.peer_stats(back).await?.ok_or("unknown peer")?;
            let counted = (out.data_tx, r#in.data_rx, out.tx);
            if counted == (bytes, bytes, r#in.rx) {
                break;
            }
            if Instant::now() > deadline {
                return Err(format!(
                    "{bytes} bytes sent; counted data tx {}, data rx {}, wire tx {} rx {}",
                    out.data_tx, r#in.data_rx, out.tx, r#in.rx
                )
                .into());
            }
            sleep(WAIT / 50).await;
        }
    }
    expect_no_drops(&a).await?;
    expect_no_drops(&b).await
}

async fn bulk_over(ip: IpAddr, offload: bool) -> TestResult {
    let pair = node(1, ip, offload).and_then(|a| Ok((a, node(2, ip, offload)?)));
    let (a, b) = match pair {
        Err(e) if ip.is_ipv6() && e.kind() == io::ErrorKind::AddrNotAvailable => {
            writeln!(io::stderr(), "skipped: cannot bind {ip}: {e}")?;
            return Ok(());
        }
        pair => pair?,
    };
    bulk_transfer(a, b).await
}

#[tokio::test]
async fn bulk_transfer_ipv4_offload_on() -> TestResult {
    bulk_over(IpAddr::V4(Ipv4Addr::LOCALHOST), true).await
}

#[tokio::test]
async fn bulk_transfer_ipv4_offload_off() -> TestResult {
    bulk_over(IpAddr::V4(Ipv4Addr::LOCALHOST), false).await
}

#[tokio::test]
async fn bulk_transfer_ipv6_offload_on() -> TestResult {
    bulk_over(IpAddr::V6(Ipv6Addr::LOCALHOST), true).await
}

#[tokio::test]
async fn bulk_transfer_ipv6_offload_off() -> TestResult {
    bulk_over(IpAddr::V6(Ipv6Addr::LOCALHOST), false).await
}

/// The MTU `lo` gets for [`fragmentation_follows_bind_time_offload`]; the minimum for IPv6.
#[cfg(target_os = "linux")]
const LOW_MTU: u16 = 1280;

/// Sets the MTU of `lo` with `ip link`.
#[cfg(target_os = "linux")]
fn set_lo_mtu(mtu: &str) -> TestResult {
    let status = std::process::Command::new("ip")
        .args(["link", "set", "dev", "lo", "mtu", mtu])
        .status()?;
    if !status.success() {
        return Err(format!("ip link set dev lo mtu {mtu}: {status}").into());
    }
    Ok(())
}

/// Sends a datagram larger than [`LOW_MTU`] over `ip` from a transport bound with and one
/// bound without offload.
#[cfg(target_os = "linux")]
async fn oversized_datagram(ip: IpAddr) -> TestResult {
    use nsplane::Transport;
    use nsplane_packet::{Ecn, Path};

    let bind = |id, offload| {
        UdpTransport::bind_with_offload(TransportId::new(id), SocketAddr::new(ip, 0), offload)
    };
    let receiver = bind(1, false)?;
    let datagram = payload(2 * usize::from(LOW_MTU));
    let to = Path {
        transport: TransportId::new(0),
        addr: receiver.local_addr(),
        ecn: Ecn::NotEct,
    };

    // Without offload the kernel fragments it, and reassembles it on receive.
    let plain = bind(2, false)?;
    plain.send(&datagram, &to).await?;
    let mut buf = PacketBuf::with_capacity(4 * usize::from(LOW_MTU));
    let (len, path) = timeout(WAIT, receiver.recv(&mut buf)).await??;
    if buf.as_packet() != datagram.as_slice() || path.addr != plain.local_addr() {
        return Err(format!("{ip}: got {len} bytes from {}", path.addr).into());
    }

    // With offload (and still with offload turned off) fragmentation is off.
    let offload = bind(3, true)?;
    for enabled in [true, false] {
        offload.set_offload(enabled)?;
        match offload.send(&datagram, &to).await {
            Err(e) if e.raw_os_error() == Some(nix::libc::EMSGSIZE) => {}
            other => return Err(format!("{ip}, offload {enabled}: sent {other:?}").into()),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN"]
async fn fragmentation_follows_bind_time_offload() -> TestResult {
    let before = std::fs::read_to_string("/sys/class/net/lo/mtu")?;
    set_lo_mtu(&LOW_MTU.to_string())?;
    let mut result = oversized_datagram(IpAddr::V4(Ipv4Addr::LOCALHOST)).await;
    if result.is_ok() {
        result = oversized_datagram(IpAddr::V6(Ipv6Addr::LOCALHOST)).await;
    }
    set_lo_mtu(before.trim())?;
    result
}
