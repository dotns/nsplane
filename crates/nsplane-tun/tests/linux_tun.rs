//! A real Linux TUN device. Needs `CAP_NET_ADMIN`, `/dev/net/tun` and `ip`:
//! `cargo test -p nsplane-tun -- --ignored`.

#![cfg(target_os = "linux")]

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::process::Command;
use std::time::Duration;

use nsplane::{PacketBuf, PacketSink, PacketSource, PeerId};
use nsplane_packet::checksum::{ipv4_header_checksum, transport_checksum_v4};
use nsplane_packet::{IpPacket, protocol};
use nsplane_tun::Tun;

const LOCAL: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 1);
const REMOTE: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 2);

#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN, /dev/net/tun and ip"]
async fn tun_device_round_trip() {
    let ip = |args: &[&str]| {
        let status = Command::new("ip").args(args).status().unwrap();
        assert!(status.success(), "ip {args:?}: {status}");
    };

    let tun = Tun::create("nsplanetest%d").unwrap();
    let name = tun.name().unwrap();
    println!("created {name} with mtu {}", tun.mtu());
    assert!(name.starts_with("nsplanetest"), "{name}");
    assert!(tun.mtu() > 0);
    ip(&["addr", "add", "10.77.0.1/24", "dev", &name]);
    ip(&["link", "set", &name, "up"]);
    let (mut source, sink) = tun.split().unwrap();

    // Kernel -> TUN: a datagram to an address routed into the device.
    let socket = UdpSocket::bind(SocketAddr::from((LOCAL, 0))).unwrap();
    socket
        .send_to(b"to the tun", SocketAddr::from((REMOTE, 4000)))
        .unwrap();
    // Skip unrelated traffic such as IPv6 router solicitations.
    loop {
        let packet = tokio::time::timeout(Duration::from_secs(5), source.recv())
            .await
            .unwrap()
            .unwrap();
        let parsed = IpPacket::parse(packet.as_packet()).unwrap();
        println!(
            "read {} bytes: {} -> {} protocol {}",
            packet.len(),
            parsed.src(),
            parsed.dst(),
            parsed.protocol()
        );
        let Some(flow) = parsed.five_tuple() else {
            continue;
        };
        if matches!(parsed, IpPacket::V4 { .. })
            && flow.protocol == protocol::UDP
            && flow.dst == REMOTE
            && flow.dst_port == 4000
        {
            assert_eq!(&parsed.payload()[8..], b"to the tun");
            break;
        }
    }

    // TUN -> kernel: a crafted datagram reaches a bound socket.
    let receiver = UdpSocket::bind(SocketAddr::from((LOCAL, 4001))).unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let payload = b"from the tun";
    let mut udp = [
        4000u16.to_be_bytes(),
        4001u16.to_be_bytes(),
        20u16.to_be_bytes(),
        [0, 0],
    ]
    .concat();
    udp.extend_from_slice(payload);
    let checksum = transport_checksum_v4(REMOTE, LOCAL, protocol::UDP, &udp);
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());
    let mut packet = vec![0x45, 0, 0, 40, 0, 1, 0x40, 0, 64, protocol::UDP, 0, 0];
    packet.extend_from_slice(&REMOTE.octets());
    packet.extend_from_slice(&LOCAL.octets());
    let checksum = ipv4_header_checksum(&packet);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet.extend_from_slice(&udp);
    sink.send(PacketBuf::from_packet(&packet), PeerId::new(0))
        .await
        .unwrap();
    let mut buf = [0u8; 64];
    let (len, from) = receiver.recv_from(&mut buf).unwrap();
    println!("socket received {len} bytes from {from}");
    assert_eq!(&buf[..len], b"from the tun");
    assert_eq!(from, SocketAddr::from((REMOTE, 4000)));
}

#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN, /dev/net/tun and ip"]
async fn tun_mtu_change_is_observed() {
    let ip = |args: &[&str]| {
        let status = Command::new("ip").args(args).status().unwrap();
        assert!(status.success(), "ip {args:?}: {status}");
    };

    let tun = Tun::create("nsplanemtu%d").unwrap();
    let name = tun.name().unwrap();
    let initial = tun.mtu();
    let (source, sink) = tun.split().unwrap();
    let mut mtu = source.mtu();
    assert_eq!(*mtu.borrow(), initial);

    for value in [1280u16, 1400] {
        ip(&["link", "set", "dev", &name, "mtu", &value.to_string()]);
        tokio::time::timeout(Duration::from_secs(5), mtu.changed())
            .await
            .unwrap()
            .unwrap();
        let observed = *mtu.borrow_and_update();
        println!("{name}: mtu {observed}");
        assert_eq!(observed, value);
    }

    // Closing the device stops the watcher, which closes the watch.
    drop((source, sink));
    let closed = tokio::time::timeout(Duration::from_secs(5), mtu.changed())
        .await
        .unwrap();
    assert!(closed.is_err());
}
