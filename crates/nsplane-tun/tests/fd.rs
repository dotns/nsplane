//! fd adoption over a `SOCK_SEQPACKET` socket pair; needs no privileges.

#![cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
))]

use std::io;
use std::net::Ipv6Addr;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::net::UnixDatagram;
use std::time::Duration;

use nsplane::{HEADROOM, PacketBuf, PacketSink, PacketSource, PeerId};
use nsplane_packet::IpPacket;
use nsplane_tun::Tun;

/// A connected socket pair keeping message boundaries, like a TUN fd. macOS has no
/// `AF_UNIX` `SOCK_SEQPACKET`, so it gets datagrams (which report no end of stream).
fn socket_pair() -> (OwnedFd, OwnedFd) {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let kind = libc::SOCK_SEQPACKET;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    let kind = libc::SOCK_DGRAM;
    let mut fds = [0; 2];
    // SAFETY: `fds` is valid for writes of two fds.
    #[allow(unsafe_code, reason = "std has no seqpacket socket pair")]
    let ret = unsafe { libc::socketpair(libc::AF_UNIX, kind, 0, fds.as_mut_ptr()) };
    assert_eq!(ret, 0, "{}", io::Error::last_os_error());
    // SAFETY: `socketpair` returned two new fds that nothing else owns.
    #[allow(unsafe_code, reason = "adopting the fds socketpair returned")]
    let pair = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    pair
}

/// `packet` as it appears on the fd: macOS/iOS prefix the utun AF header.
fn frame(packet: &[u8]) -> Vec<u8> {
    let mut framed = Vec::new();
    if cfg!(any(target_os = "macos", target_os = "ios")) {
        let af = match packet[0] >> 4 {
            4 => libc::AF_INET,
            _ => libc::AF_INET6,
        };
        framed.extend_from_slice(&af.to_be_bytes());
    }
    framed.extend_from_slice(packet);
    framed
}

/// A minimal IPv4/UDP packet carrying 8 payload bytes.
fn ipv4_udp(payload: [u8; 8]) -> Vec<u8> {
    let mut packet = vec![
        0x45, 0, 0, 36, 0, 0, 0x40, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
    ];
    let checksum = nsplane_packet::checksum::ipv4_header_checksum(&packet);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet.extend_from_slice(&[0x30, 0x39, 0x00, 0x35, 0, 16, 0, 0]);
    packet.extend_from_slice(&payload);
    packet
}

/// A minimal IPv6/UDP packet carrying 8 payload bytes.
fn ipv6_udp(payload: [u8; 8]) -> Vec<u8> {
    let mut packet = vec![0x60, 0, 0, 0, 0, 16, 17, 64];
    packet.extend_from_slice(&Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1).octets());
    packet.extend_from_slice(&Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2).octets());
    packet.extend_from_slice(&[0x30, 0x39, 0x00, 0x35, 0, 16, 0, 0]);
    packet.extend_from_slice(&payload);
    packet
}

#[tokio::test]
async fn adopted_fd_carries_packets_both_ways() {
    let (tun_fd, peer) = socket_pair();
    let peer = UnixDatagram::from(peer);
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    let tun = Tun::from_fd(tun_fd, 1420).unwrap();
    assert_eq!(tun.mtu(), 1420);
    assert!(tun.name().is_err(), "a socket pair is not a TUN device");
    let (mut source, sink) = tun.split().unwrap();
    assert_eq!(*source.mtu().borrow(), 1420);

    let packets = [ipv4_udp(*b"hello v4"), ipv6_udp(*b"hello v6")];

    // Peer -> source.
    for packet in &packets {
        peer.send(&frame(packet)).unwrap();
        let mut received = source.recv().await.unwrap();
        assert_eq!(received.as_packet(), packet.as_slice());
        assert_eq!(received.with_headroom_mut().len(), HEADROOM + packet.len());
        assert!(received.capacity() >= 1420);
        IpPacket::parse(received.as_packet()).unwrap();
    }

    // Sink -> peer.
    let mut buf = [0u8; 2048];
    for packet in &packets {
        sink.send(PacketBuf::from_packet(packet), PeerId::new(7))
            .await
            .unwrap();
        let len = peer.recv(&mut buf).unwrap();
        assert_eq!(&buf[..len], frame(packet).as_slice());
    }

    // Unknown IP version: dropped, nothing reaches the peer.
    let err = sink
        .send(PacketBuf::from_packet(&[0x50, 0, 0, 0]), PeerId::new(7))
        .await
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    let err = sink
        .send(PacketBuf::from_packet(&[]), PeerId::new(7))
        .await
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);

    // Closing the peer ends the stream, on every later call too.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        drop(peer);
        for _ in 0..2 {
            let err = source.recv().await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        }
    }
}
