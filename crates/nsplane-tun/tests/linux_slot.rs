//! `TunSlot` over real Linux TUN fds. Needs `CAP_NET_ADMIN`, `/dev/net/tun` and `ip`:
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
use nsplane_tun::{SlotSink, SlotSource, Tun, TunOptions, TunSlot};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const WAIT: Duration = Duration::from_secs(5);

#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN, /dev/net/tun and ip"]
async fn slot_round_trip_through_the_kernel() {
    let (tun, local, remote) = device("nsplaneslot%d", 20).unwrap();
    let (slot, mut source, sink) = TunSlot::new(tun.mtu());
    slot.replace(tun.as_fd().try_clone_to_owned().unwrap())
        .unwrap();

    kernel_to_slot(&mut source, local, remote, b"to the slot")
        .await
        .unwrap();
    slot_to_kernel(&sink, local, remote, b"from the slot")
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "needs CAP_NET_ADMIN, /dev/net/tun and ip"]
async fn slot_replace_moves_to_a_second_device() {
    let (first, local1, remote1) = device("nsplaneslota%d", 21).unwrap();
    let (second, local2, remote2) = device("nsplaneslotb%d", 22).unwrap();
    let (slot, mut source, sink) = TunSlot::new(first.mtu());
    slot.replace(first.as_fd().try_clone_to_owned().unwrap())
        .unwrap();
    kernel_to_slot(&mut source, local1, remote1, b"first device")
        .await
        .unwrap();
    slot_to_kernel(&sink, local1, remote1, b"first device")
        .await
        .unwrap();

    slot.replace(second.as_fd().try_clone_to_owned().unwrap())
        .unwrap();
    // A datagram routed into the first device is no longer read by the slot.
    let socket = UdpSocket::bind(SocketAddr::from((local1, 0))).unwrap();
    socket
        .send_to(b"stale", SocketAddr::from((remote1, 4000)))
        .unwrap();
    kernel_to_slot(&mut source, local2, remote2, b"second device")
        .await
        .unwrap();
    slot_to_kernel(&sink, local2, remote2, b"second device")
        .await
        .unwrap();
}

/// A plain TUN device (no virtio-net header) with `10.77.<subnet>.1/24`, up; also its
/// local address and a remote address routed into it.
fn device(name: &str, subnet: u8) -> TestResult<(Tun, Ipv4Addr, Ipv4Addr)> {
    let tun = Tun::create_with(name, TunOptions::new().offload(false))?;
    let name = tun.name()?;
    let local = Ipv4Addr::new(10, 77, subnet, 1);
    for args in [
        &["addr", "add", &format!("{local}/24"), "dev", &name][..],
        &["link", "set", &name, "up"],
    ] {
        let status = Command::new("ip").args(args).status()?;
        if !status.success() {
            return Err(format!("ip {args:?}: {status}").into());
        }
    }
    Ok((tun, local, Ipv4Addr::new(10, 77, subnet, 2)))
}

/// A datagram from a kernel socket on `local` to `remote` port 4000 is read by `source`;
/// unrelated traffic (IPv6 router solicitations, other destinations) is skipped.
async fn kernel_to_slot(
    source: &mut SlotSource,
    local: Ipv4Addr,
    remote: Ipv4Addr,
    payload: &[u8],
) -> TestResult {
    let socket = UdpSocket::bind(SocketAddr::from((local, 0)))?;
    socket.send_to(payload, SocketAddr::from((remote, 4000)))?;
    loop {
        let packet = tokio::time::timeout(WAIT, source.recv()).await??;
        let parsed = IpPacket::parse(packet.as_packet())?;
        let Some(flow) = parsed.five_tuple() else {
            continue;
        };
        if flow.protocol == protocol::UDP && flow.dst == remote && flow.dst_port == 4000 {
            if &parsed.payload()[8..] != payload {
                return Err("payload changed".into());
            }
            return Ok(());
        }
    }
}

/// A datagram from `remote` port 4000 written to `sink` reaches a kernel socket bound
/// to `local` port 4001.
async fn slot_to_kernel(
    sink: &SlotSink,
    local: Ipv4Addr,
    remote: Ipv4Addr,
    payload: &[u8],
) -> TestResult {
    let receiver = UdpSocket::bind(SocketAddr::from((local, 4001)))?;
    receiver.set_read_timeout(Some(WAIT))?;
    let udp_len = u16::try_from(8 + payload.len())?;
    let mut udp = [
        4000u16.to_be_bytes(),
        4001u16.to_be_bytes(),
        udp_len.to_be_bytes(),
        [0, 0],
    ]
    .concat();
    udp.extend_from_slice(payload);
    let checksum = transport_checksum_v4(remote, local, protocol::UDP, &udp);
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
    packet.extend_from_slice(&remote.octets());
    packet.extend_from_slice(&local.octets());
    let checksum = ipv4_header_checksum(&packet);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet.extend_from_slice(&udp);
    tokio::time::timeout(
        WAIT,
        sink.send(PacketBuf::from_packet(&packet), PeerId::new(0)),
    )
    .await??;
    let mut buf = [0u8; 256];
    let (len, from) = receiver.recv_from(&mut buf)?;
    if &buf[..len] != payload || from != SocketAddr::from((remote, 4000)) {
        return Err(format!("received {:?} from {from}", &buf[..len]).into());
    }
    Ok(())
}
