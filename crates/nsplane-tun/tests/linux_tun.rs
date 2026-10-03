//! A real Linux TUN device. Needs `CAP_NET_ADMIN`, `/dev/net/tun` and `ip`:
//! `cargo test -p nsplane-tun -- --ignored`.

#![cfg(target_os = "linux")]

use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::os::fd::AsFd;
use std::process::Command;
use std::time::Duration;

use nsplane::{PacketBuf, PacketSink, PacketSource, PeerId};
use nsplane_packet::checksum::{ipv4_header_checksum, transport_checksum_v4};
use nsplane_packet::{IpPacket, protocol};
use nsplane_tun::{Offload, Tun, TunOptions};

type TestResult = Result<(), Box<dyn Error>>;

#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN, /dev/net/tun and ip"]
async fn tun_device_round_trip() {
    let tun = Tun::create("nsplanetest%d").unwrap();
    let offload = tun.offload();
    println!("offload {offload:?}");
    assert!(offload.vnet_hdr && offload.tso, "{offload:?}");
    round_trip(tun, "nsplanetest", 0).await.unwrap();
}

#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN, /dev/net/tun and ip"]
async fn plain_tun_device_round_trip() {
    let tun = Tun::create_with("nsplaneplain%d", TunOptions::new().offload(false)).unwrap();
    assert_eq!(tun.offload(), Offload::default());
    round_trip(tun, "nsplaneplain", 1).await.unwrap();
}

#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN, /dev/net/tun and ip"]
async fn plain_tun_full_mtu_read_leaves_room_to_grow() {
    let tun = Tun::create_with("nsplanegrow%d", TunOptions::new().offload(false)).unwrap();
    let name = tun.name().unwrap();
    let mtu = usize::from(tun.mtu());
    let local = Ipv4Addr::new(10, 77, 4, 1);
    let remote = Ipv4Addr::new(10, 77, 4, 2);
    for args in [
        &["addr", "add", "10.77.4.1/24", "dev", &name][..],
        &["link", "set", &name, "up"],
    ] {
        let status = Command::new("ip").args(args).status().unwrap();
        assert!(status.success(), "ip {args:?}: {status}");
    }
    let (mut source, _sink) = tun.split().unwrap();

    // A datagram filling the MTU: 20 bytes of IPv4 and 8 of UDP header.
    let socket = UdpSocket::bind(SocketAddr::from((local, 0))).unwrap();
    socket
        .send_to(&vec![0x5a; mtu - 28], SocketAddr::from((remote, 4000)))
        .unwrap();
    loop {
        let packet = tokio::time::timeout(Duration::from_secs(5), source.recv())
            .await
            .unwrap()
            .unwrap();
        let parsed = IpPacket::parse(packet.as_packet()).unwrap();
        if matches!(parsed, IpPacket::V4 { .. })
            && parsed
                .five_tuple()
                .is_some_and(|flow| flow.dst_port == 4000)
        {
            // Room for an IPv4 -> IPv6 translator to grow it in place.
            assert_eq!(packet.len(), mtu);
            assert!(packet.capacity() >= mtu + 28, "{}", packet.capacity());
            break;
        }
    }
}

#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN, /dev/net/tun and ip"]
async fn adopted_tun_fds_round_trip() {
    // An adopted vnet-header fd reads with the header and writes without offloads.
    let created = Tun::create("nsplanevnetfd%d").unwrap();
    let fd = created.as_fd().try_clone_to_owned().unwrap();
    let adopted = Tun::from_fd(fd, created.mtu()).unwrap();
    drop(created);
    let offload = adopted.offload();
    assert!(
        offload.vnet_hdr && !offload.tso && !offload.uso,
        "{offload:?}"
    );
    round_trip(adopted, "nsplanevnetfd", 2).await.unwrap();

    // An adopted plain fd keeps today's raw framing.
    let created = Tun::create_with("nsplaneplfd%d", TunOptions::new().offload(false)).unwrap();
    let fd = created.as_fd().try_clone_to_owned().unwrap();
    let adopted = Tun::from_fd(fd, created.mtu()).unwrap();
    drop(created);
    assert_eq!(adopted.offload(), Offload::default());
    round_trip(adopted, "nsplaneplfd", 3).await.unwrap();
}

/// A datagram from a kernel socket read from `tun`, and a crafted datagram written to
/// `tun` delivered to a kernel socket, over the subnet `10.77.<subnet>.0/24`.
async fn round_trip(tun: Tun, prefix: &str, subnet: u8) -> TestResult {
    let local = Ipv4Addr::new(10, 77, subnet, 1);
    let remote = Ipv4Addr::new(10, 77, subnet, 2);
    let ip = |args: &[&str]| -> TestResult {
        let status = Command::new("ip").args(args).status()?;
        assert!(status.success(), "ip {args:?}: {status}");
        Ok(())
    };

    let name = tun.name()?;
    assert!(name.starts_with(prefix), "{name}");
    assert!(tun.mtu() > 0);
    ip(&["addr", "add", &format!("{local}/24"), "dev", &name])?;
    ip(&["link", "set", &name, "up"])?;
    let (mut source, sink) = tun.split()?;

    // Kernel -> TUN: a datagram to an address routed into the device.
    let socket = UdpSocket::bind(SocketAddr::from((local, 0)))?;
    socket.send_to(b"to the tun", SocketAddr::from((remote, 4000)))?;
    // Skip unrelated traffic such as IPv6 router solicitations.
    loop {
        let packet = tokio::time::timeout(Duration::from_secs(5), source.recv()).await??;
        let parsed = IpPacket::parse(packet.as_packet())?;
        let Some(flow) = parsed.five_tuple() else {
            continue;
        };
        if matches!(parsed, IpPacket::V4 { .. })
            && flow.protocol == protocol::UDP
            && flow.dst == remote
            && flow.dst_port == 4000
        {
            assert_eq!(&parsed.payload()[8..], b"to the tun");
            break;
        }
    }

    // TUN -> kernel: a crafted datagram reaches a bound socket.
    let receiver = UdpSocket::bind(SocketAddr::from((local, 4001)))?;
    receiver.set_read_timeout(Some(Duration::from_secs(5)))?;
    let payload = b"from the tun";
    let mut udp = [
        4000u16.to_be_bytes(),
        4001u16.to_be_bytes(),
        20u16.to_be_bytes(),
        [0, 0],
    ]
    .concat();
    udp.extend_from_slice(payload);
    let checksum = transport_checksum_v4(remote, local, protocol::UDP, &udp);
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());
    let mut packet = vec![0x45, 0, 0, 40, 0, 1, 0x40, 0, 64, protocol::UDP, 0, 0];
    packet.extend_from_slice(&remote.octets());
    packet.extend_from_slice(&local.octets());
    let checksum = ipv4_header_checksum(&packet);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet.extend_from_slice(&udp);
    sink.send(PacketBuf::from_packet(&packet), PeerId::new(0))
        .await?;
    let mut buf = [0u8; 64];
    let (len, from) = receiver.recv_from(&mut buf)?;
    assert_eq!(&buf[..len], b"from the tun");
    assert_eq!(from, SocketAddr::from((remote, 4000)));
    Ok(())
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
