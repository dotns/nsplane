//! An engine whose local side is a `TunSlot`, with its fd swapped mid-transfer: packets
//! after a swap arrive in order and once, and nothing is written to a replaced fd. And
//! with its fd cleared: the fd closes at once and traffic resumes on the next one.

#![cfg(target_os = "linux")]

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::OwnedFd;
use std::time::Duration;

use nsplane::x25519::{PublicKey, StaticSecret};
use nsplane::{AllowedIp, ChannelTransport, Engine, EngineBuilder, Peer};
use nsplane_e2e::{MTU, Node, Options, QUIET, TestResult, WAIT, udp4};
use nsplane_packet::{Ecn, Path, TransportId};
use nsplane_tun::TunSlot;
use tokio::net::UnixDatagram;
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};

/// The slot engine's tunnel address; the channel node has `10.0.0.2`.
const SLOT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
/// Packets per direction.
const COUNT: u32 = 300;
/// A plain replace before this packet.
const SWAP: u32 = 100;
/// A replace between disable and enable before this packet.
const PARKED_SWAP: u32 = 200;
/// Packets sent while the slot is disabled after `PARKED_SWAP`.
const PARKED: u32 = 5;
const WARM_UP: &[u8] = b"warm-up!";

/// The slot's end as an fd and the host's end as a tokio socket.
fn pair() -> io::Result<(OwnedFd, UnixDatagram)> {
    let (slot, host) = std::os::unix::net::UnixDatagram::pair()?;
    host.set_nonblocking(true)?;
    Ok((OwnedFd::from(slot), UnixDatagram::from_std(host)?))
}

/// Forwards every datagram the host reads from `host` until reading fails.
fn reader(host: UnixDatagram) -> mpsc::UnboundedReceiver<Vec<u8>> {
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        while let Ok(len) = host.recv(&mut buf).await {
            if tx.send(buf[..len].to_vec()).is_err() {
                break;
            }
        }
    });
    rx
}

/// The number a numbered packet from `src` to `dst` carries, after checking it is intact.
fn number(packet: &[u8], src: Ipv4Addr, dst: Ipv4Addr) -> TestResult<u32> {
    let n = u32::from_be_bytes(packet.get(28..32).ok_or("short packet")?.try_into()?);
    if packet != udp4(src, dst, &n.to_be_bytes()) {
        return Err(format!("packet {n} changed in transit").into());
    }
    Ok(n)
}

fn strictly_increasing(numbers: &[u32]) -> bool {
    numbers.windows(2).all(|w| w[0] < w[1])
}

/// An engine on a slot, peered over a channel transport with a [`Node`].
async fn setup() -> TestResult<(Engine, TunSlot, Node<ChannelTransport>)> {
    let a = (
        TransportId::new(1),
        SocketAddr::from(([192, 0, 2, 1], 1000)),
    );
    let b = (
        TransportId::new(2),
        SocketAddr::from(([192, 0, 2, 2], 2000)),
    );
    let (link_a, link_b) = ChannelTransport::pair(1024, a, b);
    let (slot, source, sink) = TunSlot::new(MTU);
    let secret = StaticSecret::from([1; 32]);
    let public = PublicKey::from(&secret);
    let engine = EngineBuilder::new(source, sink)
        .private_key(secret)
        .transport(link_a)
        .build()?;
    let node = Node::new(2, b.0, b.1, link_b, Options::default());

    engine
        .handle()
        .add_or_update_peer(node.as_peer(a.0))
        .await?;
    node.handle
        .add_or_update_peer(Peer {
            allowed_ips: vec![AllowedIp {
                addr: IpAddr::V4(SLOT_IP),
                cidr: 32,
            }],
            path: Some(Path {
                transport: b.0,
                addr: a.1,
                ecn: Ecn::NotEct,
            }),
            ..Peer::new(public)
        })
        .await?;
    Ok((engine, slot, node))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn numbered_streams_survive_fd_swaps() -> TestResult {
    let (_engine, slot, mut node) = setup().await?;
    let peer_ip = node.ip4;
    let (fd, mut host) = pair()?;
    slot.replace(fd)?;

    // Warm-up both ways, which also completes the handshake.
    host.send(&udp4(SLOT_IP, peer_ip, WARM_UP)).await?;
    let (_, delivered) = node.expect_delivery().await?;
    assert_eq!(delivered, udp4(SLOT_IP, peer_ip, WARM_UP));
    node.send(&udp4(peer_ip, SLOT_IP, WARM_UP)).await?;
    let mut buf = [0u8; 64];
    let len = timeout(WAIT, host.recv(&mut buf)).await??;
    assert_eq!(buf[..len], udp4(peer_ip, SLOT_IP, WARM_UP));

    // Host -> engine: what the node receives. Engine -> host: what each host socket reads.
    let mut forward = Vec::new();
    let mut readers = Vec::new();
    for n in 0..COUNT {
        if n == SWAP || n == PARKED_SWAP {
            if n == PARKED_SWAP {
                // Whatever was sent on the fd about to go must not be lost to this swap.
                while forward.last() != Some(&(n - 1)) {
                    forward.push(number(&node.expect_delivery().await?.1, SLOT_IP, peer_ip)?);
                }
                slot.disable();
            }
            let (fd, next) = pair()?;
            slot.replace(fd)?;
            readers.push(reader(std::mem::replace(&mut host, next)));
        }
        if n == PARKED_SWAP + PARKED {
            slot.enable();
        }
        host.send(&udp4(SLOT_IP, peer_ip, &n.to_be_bytes())).await?;
        node.send(&udp4(peer_ip, SLOT_IP, &n.to_be_bytes())).await?;
    }
    let mut last = reader(host);

    while forward.last() != Some(&(COUNT - 1)) {
        forward.push(number(&node.expect_delivery().await?.1, SLOT_IP, peer_ip)?);
    }
    assert!(strictly_increasing(&forward), "{forward:?}");
    assert!(
        (SWAP..COUNT).all(|n| forward.contains(&n)),
        "missing packets after a swap: {forward:?}"
    );
    node.expect_no_delivery().await?;

    // Every packet reaches the host: the sink retries a write parked on a replaced fd on
    // the new one, and the host still reads what was queued on the old one.
    let mut on_last = Vec::new();
    while on_last.last() != Some(&(COUNT - 1)) {
        let packet = timeout(WAIT, last.recv()).await?.ok_or("reader ended")?;
        on_last.push(number(&packet, peer_ip, SLOT_IP)?);
    }
    sleep(QUIET).await;
    let mut by_fd = Vec::new();
    for rx in &mut readers {
        let mut numbers = Vec::new();
        while let Ok(packet) = rx.try_recv() {
            numbers.push(number(&packet, peer_ip, SLOT_IP)?);
        }
        by_fd.push(numbers);
    }
    by_fd.push(on_last);
    // Nothing written to a replaced fd after its replace: the first fd only carries
    // packets the node sent before the first swap, the second before the second.
    for (numbers, swap) in by_fd.iter().zip([SWAP, PARKED_SWAP]) {
        assert!(numbers.iter().all(|&n| n < swap), "{by_fd:?}");
    }
    let reverse: Vec<u32> = by_fd.concat();
    assert_eq!(reverse, (0..COUNT).collect::<Vec<_>>(), "{by_fd:?}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cleared_fd_closes_and_traffic_resumes_on_the_next() -> TestResult {
    /// Packets the node sends while the slot is empty.
    const HELD: u32 = 5;
    let (_engine, slot, mut node) = setup().await?;
    let peer_ip = node.ip4;
    let (fd, host) = pair()?;
    slot.replace(fd)?;

    host.send(&udp4(SLOT_IP, peer_ip, WARM_UP)).await?;
    let (_, delivered) = node.expect_delivery().await?;
    assert_eq!(delivered, udp4(SLOT_IP, peer_ip, WARM_UP));
    node.send(&udp4(peer_ip, SLOT_IP, WARM_UP)).await?;
    let mut buf = [0u8; 64];
    let len = timeout(WAIT, host.recv(&mut buf)).await??;
    assert_eq!(buf[..len], udp4(peer_ip, SLOT_IP, WARM_UP));

    slot.clear();
    // The engine's end of the cleared fd closes once its parked I/O let go of it.
    timeout(WAIT, async {
        while host.send(WARM_UP).await.is_ok() {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    for n in 0..HELD {
        node.send(&udp4(peer_ip, SLOT_IP, &n.to_be_bytes())).await?;
    }
    sleep(QUIET).await;
    assert!(
        host.try_recv(&mut buf).is_err(),
        "a packet reached the cleared fd"
    );

    let (fd, host) = pair()?;
    slot.replace(fd)?;
    // What the node sent while the slot was empty waited for the new fd.
    let mut held = Vec::new();
    for _ in 0..HELD {
        let len = timeout(WAIT, host.recv(&mut buf)).await??;
        held.push(number(
            buf.get(..len).ok_or("long packet")?,
            peer_ip,
            SLOT_IP,
        )?);
    }
    assert_eq!(held, (0..HELD).collect::<Vec<_>>());
    host.send(&udp4(SLOT_IP, peer_ip, &HELD.to_be_bytes()))
        .await?;
    let (_, delivered) = node.expect_delivery().await?;
    assert_eq!(number(&delivered, SLOT_IP, peer_ip)?, HELD);
    Ok(())
}
