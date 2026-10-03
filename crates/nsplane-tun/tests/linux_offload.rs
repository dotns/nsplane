//! Segmentation offloads of a real Linux TUN device. Needs `CAP_NET_ADMIN`,
//! `/dev/net/tun` and `ip`: `cargo test -p nsplane-tun -- --ignored`.
//!
//! The kernel's TCP and UDP traffic crosses the device to and from userspace; the
//! device's packet counters (one per read or write) show that reads carried several
//! packets and that coalesced writes were accepted.

#![cfg(target_os = "linux")]

use std::collections::VecDeque;
use std::error::Error;
use std::future::poll_fn;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpStream, UdpSocket};
use std::pin::Pin;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures_core::Stream;
use nsplane::{MAX_BATCH, PacketBatch, PacketBuf, PacketSink, PacketSource, PeerId};
use nsplane_netstack::{NetStack, NetStackConfig, NetStackHandle, NetStackSink, NetStackSource};
use nsplane_packet::checksum::{ipv4_header_checksum, transport_checksum_v4};
use nsplane_packet::{IpPacket, protocol};
use nsplane_tun::{Tun, TunSink, TunSource};
use tokio::io::AsyncWriteExt;

type TestResult = Result<(), Box<dyn Error>>;

/// Bytes the kernel sends through the device, and receives back.
const FLOW_BYTES: usize = 1 << 20;

fn ip(args: &[&str]) -> TestResult {
    let status = Command::new("ip").args(args).status()?;
    assert!(status.success(), "ip {args:?}: {status}");
    Ok(())
}

/// Creates an offload device with `local/24`, brings it up and returns its name.
fn device(pattern: &str, local: Ipv4Addr) -> Result<(Tun, String), Box<dyn Error>> {
    let tun = Tun::create(pattern)?;
    let name = tun.name()?;
    ip(&["addr", "add", &format!("{local}/24"), "dev", &name])?;
    ip(&["link", "set", &name, "up"])?;
    Ok((tun, name))
}

/// A packet counter of interface `name`, e.g. `tx_packets` (kernel to device reads).
fn counter(name: &str, stat: &str) -> Result<usize, Box<dyn Error>> {
    let value = std::fs::read_to_string(format!("/sys/class/net/{name}/statistics/{stat}"))?;
    Ok(value.trim().parse()?)
}

/// Whether `packet` is an IPv4 TCP or UDP packet with valid checksums.
fn checksums_valid(packet: &[u8]) -> bool {
    let Ok(parsed @ IpPacket::V4 { payload, .. }) = IpPacket::parse(packet) else {
        return false;
    };
    let (IpAddr::V4(src), IpAddr::V4(dst)) = (parsed.src(), parsed.dst()) else {
        return false;
    };
    let ihl = usize::from(packet[0] & 0x0F) * 4;
    let at = match packet[9] {
        protocol::TCP => 16,
        protocol::UDP => 6,
        _ => return false,
    };
    let mut l4 = payload.to_vec();
    let stored = u16::from_be_bytes([l4[at], l4[at + 1]]);
    l4[at..at + 2].fill(0);
    ipv4_header_checksum(&packet[..ihl]) == u16::from_be_bytes([packet[10], packet[11]])
        && transport_checksum_v4(src, dst, packet[9], &l4) == stored
}

/// What the forwarders between the device and the stack saw.
#[derive(Debug, Default)]
struct Counts {
    read_packets: AtomicUsize,
    largest_read: AtomicUsize,
    invalid: AtomicUsize,
    written_packets: AtomicUsize,
}

/// Device -> stack: every packet must be a valid packet within the MTU.
async fn forward_reads(
    mut source: TunSource,
    sink: NetStackSink,
    mtu: u16,
    counts: Arc<Counts>,
) -> io::Result<()> {
    let mut batch = PacketBatch::new();
    let mut queue = VecDeque::new();
    loop {
        source.recv_batch(&mut batch).await?;
        counts
            .largest_read
            .fetch_max(batch.len(), Ordering::Relaxed);
        counts
            .read_packets
            .fetch_add(batch.len(), Ordering::Relaxed);
        for packet in batch.drain() {
            let bytes = packet.as_packet();
            if bytes.len() > usize::from(mtu) || (bytes[0] >> 4 == 4 && !checksums_valid(bytes)) {
                counts.invalid.fetch_add(1, Ordering::Relaxed);
            }
            queue.push_back((PeerId::new(0), packet));
        }
        sink.send_batch(&mut queue).await?;
    }
}

/// Stack -> device: whatever the stack has ready goes out as one batch.
async fn forward_writes(
    mut source: NetStackSource,
    sink: TunSink,
    counts: Arc<Counts>,
) -> io::Result<()> {
    let mut queue = VecDeque::new();
    loop {
        let first = source.recv().await?;
        queue.push_back((PeerId::new(0), first));
        while queue.len() < MAX_BATCH {
            tokio::select! {
                biased;
                packet = source.recv() => queue.push_back((PeerId::new(0), packet?)),
                () = std::future::ready(()) => break,
            }
        }
        counts
            .written_packets
            .fetch_add(queue.len(), Ordering::Relaxed);
        sink.send_batch(&mut queue).await?;
    }
}

/// Accepts one connection on the stack and echoes it.
async fn echo(handle: NetStackHandle) -> io::Result<()> {
    let mut incoming = handle.incoming_tcp();
    let conn = poll_fn(|cx| Pin::new(&mut incoming).poll_next(cx))
        .await
        .ok_or_else(|| io::Error::other("no connection"))?;
    let (mut reader, mut writer) = tokio::io::split(conn);
    tokio::io::copy(&mut reader, &mut writer).await?;
    writer.shutdown().await?;
    Ok(())
}

/// The kernel's side: sends [`FLOW_BYTES`] to `remote` and expects them back.
fn kernel_flow(remote: Ipv4Addr) -> TestResult {
    let data: Vec<u8> = (0..FLOW_BYTES)
        .map(|i| (i % 251).to_le_bytes()[0])
        .collect();
    let stream =
        TcpStream::connect_timeout(&SocketAddr::from((remote, 5000)), Duration::from_secs(5))?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut writer = stream.try_clone()?;
    let sent = data.clone();
    let sender = std::thread::spawn(move || -> io::Result<()> {
        writer.write_all(&sent)?;
        writer.shutdown(Shutdown::Write)
    });
    let mut echoed = Vec::new();
    (&stream).read_to_end(&mut echoed)?;
    sender.join().map_err(|_| "sender panicked")??;
    assert_eq!(echoed.len(), data.len());
    assert!(echoed == data, "echoed bytes differ");
    Ok(())
}

#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN, /dev/net/tun and ip"]
async fn tcp_flow_through_offload_device() {
    let local = Ipv4Addr::new(10, 78, 0, 1);
    let remote = Ipv4Addr::new(10, 78, 0, 2);
    let (tun, name) = device("nsplanetso%d", local).unwrap();
    println!("{name}: mtu {}, offload {:?}", tun.mtu(), tun.offload());
    assert!(tun.offload().tso, "{:?}", tun.offload());
    let mtu = tun.mtu();
    let (tun_source, tun_sink) = tun.split().unwrap();
    let (stack, handle) = NetStack::new(NetStackConfig::new(vec![(remote.into(), 24)], mtu));
    let (stack_source, stack_sink) = stack.split();
    let counts = Arc::new(Counts::default());
    let reads_task = tokio::spawn(forward_reads(tun_source, stack_sink, mtu, counts.clone()));
    let writes_task = tokio::spawn(forward_writes(stack_source, tun_sink, counts.clone()));
    let echo = tokio::spawn(echo(handle));

    let tx_before = counter(&name, "tx_packets").unwrap();
    let rx_before = counter(&name, "rx_packets").unwrap();
    let read_before = counts.read_packets.load(Ordering::Relaxed);
    let kernel =
        tokio::task::spawn_blocking(move || kernel_flow(remote).map_err(|e| e.to_string()));
    tokio::time::timeout(Duration::from_secs(60), kernel)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), echo)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let reads = counter(&name, "tx_packets").unwrap() - tx_before;
    let writes = counter(&name, "rx_packets").unwrap() - rx_before;
    reads_task.abort();
    writes_task.abort();

    let read_packets = counts.read_packets.load(Ordering::Relaxed) - read_before;
    let written_packets = counts.written_packets.load(Ordering::Relaxed);
    let largest_read = counts.largest_read.load(Ordering::Relaxed);
    println!(
        "{read_packets} packets in {reads} reads (at most {largest_read} per read), \
         {written_packets} packets in {writes} writes"
    );
    assert_eq!(counts.invalid.load(Ordering::Relaxed), 0);
    // GSO reads: the kernel handed over super-packets that were split.
    assert!(largest_read > 1);
    assert!(
        reads < read_packets,
        "{reads} reads, {read_packets} packets"
    );
    // Coalesced writes: fewer writes than packets, and the payload arrived intact.
    assert!(
        writes < written_packets,
        "{writes} writes, {written_packets} packets"
    );
}

#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN, /dev/net/tun and ip"]
async fn udp_super_packets_reach_the_kernel() {
    let local = Ipv4Addr::new(10, 79, 0, 1);
    let remote = Ipv4Addr::new(10, 79, 0, 2);
    let (tun, name) = device("nsplaneuso%d", local).unwrap();
    println!("{name}: mtu {}, offload {:?}", tun.mtu(), tun.offload());
    if !tun.offload().uso {
        println!("skipped: the kernel does not accept UDP segmentation offload (TUN_F_USO4/6)");
        return;
    }
    let (_source, sink) = tun.split().unwrap();
    let receiver = UdpSocket::bind(SocketAddr::from((local, 6000))).unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let count = 20u8;
    let mut packets = VecDeque::new();
    for i in 0..count {
        let payload = vec![i; 1000];
        let mut udp = [
            6001u16.to_be_bytes(),
            6000u16.to_be_bytes(),
            1008u16.to_be_bytes(),
            [0, 0],
        ]
        .concat();
        udp.extend_from_slice(&payload);
        let checksum = transport_checksum_v4(remote, local, protocol::UDP, &udp);
        udp[6..8].copy_from_slice(&checksum.to_be_bytes());
        let mut packet = vec![0x45, 0, 0x04, 0x04, 0, i, 0x40, 0, 64, protocol::UDP, 0, 0];
        packet.extend_from_slice(&remote.octets());
        packet.extend_from_slice(&local.octets());
        let checksum = ipv4_header_checksum(&packet);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet.extend_from_slice(&udp);
        packets.push_back((PeerId::new(0), PacketBuf::from_packet(&packet)));
    }
    let before = counter(&name, "rx_packets").unwrap();
    sink.send_batch(&mut packets).await.unwrap();
    let writes = counter(&name, "rx_packets").unwrap() - before;

    let mut buf = [0u8; 2000];
    for i in 0..count {
        let (len, from) = receiver.recv_from(&mut buf).unwrap();
        assert_eq!(from, SocketAddr::from((remote, 6001)));
        assert_eq!(&buf[..len], &[i; 1000][..]);
    }
    println!("{count} datagrams in {writes} writes");
    assert!(writes < usize::from(count), "{writes} writes");
}
