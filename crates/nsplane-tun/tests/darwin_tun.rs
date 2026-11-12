//! A real macOS utun interface. Needs administrator privileges and `ifconfig`:
//! `sudo cargo test -p nsplane-tun -- --ignored --test-threads 1`.

#![cfg(target_os = "macos")]

use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::os::fd::AsFd;
use std::process::Command;
use std::time::Duration;

use nsplane::{PacketBuf, PacketSink, PacketSource, PeerId};
use nsplane_packet::checksum::{ipv4_header_checksum, transport_checksum_v4};
use nsplane_packet::{IpPacket, protocol};
use nsplane_tun::{Tun, TunSlot};
use tokio::time::timeout;

type TestResult = Result<(), Box<dyn Error>>;

const WAIT: Duration = Duration::from_secs(5);

fn ifconfig(args: &[&str]) -> TestResult {
    let output = Command::new("ifconfig").args(args).output()?;
    assert!(output.status.success(), "ifconfig {args:?}: {output:?}");
    Ok(())
}

/// The addresses of the point-to-point link `10.77.<subnet>.1 -> 10.77.<subnet>.2` set on
/// the interface `name`.
fn addresses(name: &str, subnet: u8) -> Result<(Ipv4Addr, Ipv4Addr), Box<dyn Error>> {
    let local = Ipv4Addr::new(10, 77, subnet, 1);
    let remote = Ipv4Addr::new(10, 77, subnet, 2);
    ifconfig(&[name, "inet", &local.to_string(), &remote.to_string(), "up"])?;
    Ok((local, remote))
}

/// Reads from `source` until the UDP datagram to `remote` port 4000 arrives; skips
/// unrelated traffic.
async fn datagram_to(
    source: &mut impl PacketSource,
    remote: Ipv4Addr,
) -> Result<PacketBuf, Box<dyn Error>> {
    loop {
        let packet = timeout(WAIT, source.recv()).await??;
        let parsed = IpPacket::parse(packet.as_packet())?;
        let Some(flow) = parsed.five_tuple() else {
            continue;
        };
        if matches!(parsed, IpPacket::V4 { .. })
            && flow.protocol == protocol::UDP
            && flow.dst == remote
            && flow.dst_port == 4000
        {
            return Ok(packet);
        }
    }
}

/// An IPv4 UDP datagram from `src` port 4000 to `dst` port 4001 carrying `payload`.
fn datagram(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let udp_len = u16::try_from(8 + payload.len())?;
    let mut udp = [
        4000u16.to_be_bytes(),
        4001u16.to_be_bytes(),
        udp_len.to_be_bytes(),
        [0, 0],
    ]
    .concat();
    udp.extend_from_slice(payload);
    let checksum = transport_checksum_v4(src, dst, protocol::UDP, &udp);
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());
    let total = (20 + udp_len).to_be_bytes();
    let mut packet = vec![
        0x45,
        0,
        total[0],
        total[1],
        0,
        1,
        0x40,
        0,
        64,
        protocol::UDP,
        0,
        0,
    ];
    packet.extend_from_slice(&src.octets());
    packet.extend_from_slice(&dst.octets());
    let checksum = ipv4_header_checksum(&packet);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet.extend_from_slice(&udp);
    Ok(packet)
}

/// A datagram from a socket is read from `source` without the utun header, and a crafted
/// datagram written to `sink` reaches a bound socket.
async fn round_trip(
    source: &mut impl PacketSource,
    sink: &impl PacketSink,
    local: Ipv4Addr,
    remote: Ipv4Addr,
) -> TestResult {
    let socket = UdpSocket::bind(SocketAddr::from((local, 0)))?;
    socket.send_to(b"to the tun", SocketAddr::from((remote, 4000)))?;
    let packet = datagram_to(source, remote).await?;
    let parsed = IpPacket::parse(packet.as_packet())?;
    assert_eq!(&parsed.payload()[8..], b"to the tun");

    let receiver = UdpSocket::bind(SocketAddr::from((local, 4001)))?;
    receiver.set_read_timeout(Some(WAIT))?;
    let packet = datagram(remote, local, b"from the tun")?;
    sink.send(PacketBuf::from_packet(&packet), PeerId::new(0))
        .await?;
    let mut buf = [0u8; 64];
    let (len, from) = receiver.recv_from(&mut buf)?;
    assert_eq!(&buf[..len], b"from the tun");
    assert_eq!(from, SocketAddr::from((remote, 4000)));
    Ok(())
}

#[tokio::test]
#[ignore = "needs administrator privileges to create a utun interface"]
async fn utun_device_round_trip() -> TestResult {
    let tun = Tun::create("utun")?;
    let name = tun.name()?;
    let (local, remote) = addresses(&name, 21)?;
    let (mut source, sink) = tun.split()?;
    round_trip(&mut source, &sink, local, remote).await
}

/// A utun socket installed in a `TunSlot` is framed like a created device: packets are
/// read without the 4-byte header and written with it.
#[tokio::test]
#[ignore = "needs administrator privileges to create a utun interface"]
async fn utun_fd_in_a_slot_round_trip() -> TestResult {
    let tun = Tun::create("utun")?;
    let name = tun.name()?;
    let (local, remote) = addresses(&name, 22)?;
    let fd = tun.as_fd().try_clone_to_owned()?;
    let (slot, mut source, sink) = TunSlot::new(tun.mtu());
    slot.replace(fd)?;
    drop(tun);
    round_trip(&mut source, &sink, local, remote).await?;
    assert_eq!(source.oversize_drops(), 0);
    Ok(())
}

/// A packet longer than the MTU the source knew when it sized its read is read whole.
#[tokio::test]
#[ignore = "needs administrator privileges to create a utun interface"]
async fn packet_longer_than_the_known_mtu_is_read_whole() -> TestResult {
    let tun = Tun::create("utun")?;
    let name = tun.name()?;
    let known = usize::from(tun.mtu());
    let (local, remote) = addresses(&name, 23)?;
    let (mut source, _sink) = tun.split()?;

    // Raised behind the source's back: the datagram is sent before the MTU watcher can
    // report the change.
    let raised = known + 2000;
    ifconfig(&[&name, "mtu", &raised.to_string()])?;
    let payload = vec![0x5a; raised - 28];
    let socket = UdpSocket::bind(SocketAddr::from((local, 0)))?;
    socket.send_to(&payload, SocketAddr::from((remote, 4000)))?;
    let packet = datagram_to(&mut source, remote).await?;
    assert_eq!(packet.len(), raised);
    let parsed = IpPacket::parse(packet.as_packet())?;
    assert_eq!(&parsed.payload()[8..], &payload[..]);
    Ok(())
}
