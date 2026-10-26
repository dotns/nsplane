//! Shared helpers of the `Translator` tests: addresses and checks of translated packets.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use nsplane::{AllowedIp, ChannelTransport};
use nsplane_packet::{Ipv4Header, Ipv6Header};

use crate::{Node, TestResult, verify_checksums};

/// Node `a`'s own IPv4 address, translated to and from `SELF_EAM6`.
pub const SELF_EAM4: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 100);
/// Node `a`'s own IPv6 address, translated to and from `SELF_EAM4`.
pub const SELF_EAM6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0xff, 1);

/// TCP flag SYN.
pub const SYN: u8 = 0x02;
/// TCP flag ACK.
pub const ACK: u8 = 0x10;
/// TCP flags PSH and ACK.
pub const PSH_ACK: u8 = 0x18;

/// A node of the translation tests.
pub type TestNode = Node<ChannelTransport>;

/// The allowed IP `addr/cidr`.
pub fn allowed(addr: impl Into<IpAddr>, cidr: u8) -> AllowedIp {
    AllowedIp {
        addr: addr.into(),
        cidr,
    }
}

/// The IPv4 socket address `ip:port`.
pub const fn v4(ip: Ipv4Addr, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(ip), port)
}

/// The IPv6 socket address `[ip]:port`.
pub const fn v6(ip: Ipv6Addr, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V6(ip), port)
}

/// The address of `host` inside the /96 LAN prefix `prefix`.
pub fn lan6(prefix: Ipv6Addr, host: Ipv4Addr) -> Ipv6Addr {
    Ipv6Addr::from(u128::from(prefix) | u128::from(u32::from(host)))
}

/// The next packet `node` delivers, checked to be IPv6 from `src` to `dst` with protocol
/// `proto`, a hop limit of 63 and valid checksums; returns its transport segment.
pub async fn expect_v6(
    node: &mut TestNode,
    (src, dst): (Ipv6Addr, Ipv6Addr),
    proto: u8,
) -> TestResult<Vec<u8>> {
    let (_, packet) = node.expect_delivery().await?;
    verify_checksums(&packet)?;
    let (ip, segment) = Ipv6Header::parse(&packet)?;
    assert_eq!((ip.src(), ip.dst()), (src, dst));
    assert_eq!((ip.next_header(), ip.hop_limit()), (proto, 63));
    Ok(segment.to_vec())
}

/// The next packet `node` delivers, checked to be IPv4 from `src` to `dst` with protocol
/// `proto`, a TTL of 63 and valid checksums; returns its transport segment.
pub async fn expect_v4(
    node: &mut TestNode,
    (src, dst): (Ipv4Addr, Ipv4Addr),
    proto: u8,
) -> TestResult<Vec<u8>> {
    let (_, packet) = node.expect_delivery().await?;
    verify_checksums(&packet)?;
    let (ip, segment) = Ipv4Header::parse(&packet)?;
    assert_eq!((ip.src(), ip.dst()), (src, dst));
    assert_eq!((ip.protocol(), ip.ttl()), (proto, 63));
    Ok(segment.to_vec())
}

/// The transport segment of `packet`.
pub fn segment(packet: &[u8]) -> &[u8] {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => &packet[20..],
        _ => &packet[40..],
    }
}

/// Checks that the translated segment `got` equals the segment of `sent` except for the
/// checksum at `checksum` (moved to the new pseudo-header).
pub fn assert_same_segment(got: &[u8], sent: &[u8], checksum: usize) {
    let sent = segment(sent);
    assert_eq!(got.len(), sent.len());
    assert_eq!(got[..checksum], sent[..checksum]);
    assert_eq!(got[checksum + 2..], sent[checksum + 2..]);
}
