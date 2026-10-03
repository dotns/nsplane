//! In-place address and port rewriting with incremental checksum updates.
//!
//! A `None` means the packet is too short or of the wrong address family;
//! the filter drops such a packet.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use nsplane_packet::{FiveTuple, IpPacket, protocol};

use crate::checksum;

/// Length of the ICMP / `ICMPv6` error header before the quoted packet.
const ICMP_ERROR_HEADER_LEN: usize = 8;
/// Offset of the IPv4 header checksum.
const IPV4_CHECKSUM: usize = 10;
/// Offset of the ICMP / `ICMPv6` checksum in the ICMP header.
const ICMP_CHECKSUM: usize = 2;

/// Which address and port of a packet to rewrite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum End {
    /// The source.
    Src,
    /// The destination.
    Dst,
}

/// Rewrites the `end` address and port of the TCP/UDP packet in `packet`,
/// whose transport header starts at `l4`.
pub(crate) fn endpoint(
    packet: &mut [u8],
    l4: usize,
    end: End,
    addr: IpAddr,
    port: u16,
) -> Option<()> {
    let protocol = ip_protocol(packet, 0)?;
    rewrite_at(packet, 0, l4, protocol, (end, addr, port), false)
}

/// An ICMP or `ICMPv6` error quoting a TCP/UDP packet.
#[derive(Debug, Clone, Copy)]
pub(super) struct IcmpError {
    /// Offset of the ICMP header.
    l4: usize,
    /// End of the ICMP message.
    end: usize,
    /// Offset of the quoted IP header.
    inner_ip: usize,
    /// Offset of the quoted transport header.
    inner_l4: usize,
    /// The flow key of the quoted packet.
    pub(super) inner: FiveTuple,
}

impl IcmpError {
    /// Parses an unfragmented ICMP destination unreachable, time exceeded or
    /// parameter problem error (and `ICMPv6` packet too big) whose quoted
    /// packet is an unfragmented (or first-fragment) TCP/UDP packet of the
    /// same family with at least its ports.
    pub(super) fn parse(packet: &[u8]) -> Option<Self> {
        let ip = IpPacket::parse(packet).ok()?;
        if ip.fragment().is_some() {
            return None;
        }
        let (l4, v6) = match &ip {
            IpPacket::V4 { header, .. } => (header.header_len(), false),
            IpPacket::V6 { .. } => (IPV6_HEADER_LEN, true),
        };
        let icmp_type = *ip.payload().first()?;
        let error = match ip.protocol() {
            protocol::ICMP => matches!(icmp_type, 3 | 11 | 12),
            protocol::ICMPV6 => matches!(icmp_type, 1..=4),
            _ => false,
        };
        if !error {
            return None;
        }
        let end = l4.checked_add(ip.payload().len())?;
        let inner_ip = l4 + ICMP_ERROR_HEADER_LEN;
        let quoted = packet.get(inner_ip..end)?;
        let (header_len, protocol, src, dst) = match quoted.first()? >> 4 {
            4 if !v6 => {
                let header_len = usize::from(quoted.first()? & 0x0f) * 4;
                let offset = read_u16(quoted, 6)? & 0x1fff;
                if header_len < 20 || offset != 0 {
                    return None;
                }
                (
                    header_len,
                    *quoted.get(9)?,
                    IpAddr::V4(Ipv4Addr::from(read::<4>(quoted, 12)?)),
                    IpAddr::V4(Ipv4Addr::from(read::<4>(quoted, 16)?)),
                )
            }
            6 if v6 => (
                IPV6_HEADER_LEN,
                *quoted.get(6)?,
                IpAddr::V6(Ipv6Addr::from(read::<16>(quoted, 8)?)),
                IpAddr::V6(Ipv6Addr::from(read::<16>(quoted, 24)?)),
            ),
            _ => return None,
        };
        if !matches!(protocol, protocol::TCP | protocol::UDP) {
            return None;
        }
        Some(Self {
            l4,
            end,
            inner_ip,
            inner_l4: inner_ip + header_len,
            inner: FiveTuple {
                src,
                dst,
                protocol,
                src_port: read_u16(quoted, header_len)?,
                dst_port: read_u16(quoted, header_len + 2)?,
            },
        })
    }

    /// Rewrites the quoted packet's `inner.0` address and port to `inner.1`
    /// and `inner.2`, and the outer `outer.0` address to `outer.2` when it is
    /// `outer.1`, updating every checksum involved.
    pub(super) fn rewrite(
        &self,
        packet: &mut [u8],
        inner: (End, IpAddr, u16),
        outer: (End, IpAddr, IpAddr),
    ) -> Option<()> {
        let (outer_end, outer_from, outer_to) = outer;
        if outer_from.is_ipv4() != outer_to.is_ipv4() {
            return None;
        }
        let message = self.l4..self.end;
        let checksum_at = self.l4 + ICMP_CHECKSUM;
        let old_sum = checksum::sum(packet.get(message.clone())?);
        let mut icmp_checksum = read_u16(packet, checksum_at)?;

        rewrite_at(
            packet.get_mut(..self.end)?,
            self.inner_ip,
            self.inner_l4,
            self.inner.protocol,
            inner,
            true,
        )?;
        // The checksum field is in both sums, so it cancels out.
        let new_sum = checksum::sum(packet.get(message)?);
        icmp_checksum = checksum::update_u16(icmp_checksum, old_sum, new_sum);

        let addr_at = addr_offset(packet, 0, outer_end)?;
        if read_addr(packet, addr_at, outer_from.is_ipv4())? == outer_from {
            match (outer_from, outer_to) {
                (IpAddr::V4(from), IpAddr::V4(to)) => {
                    let ip_checksum = read_u16(packet, IPV4_CHECKSUM)?;
                    write_u16(
                        packet,
                        IPV4_CHECKSUM,
                        checksum::update_ipv4(ip_checksum, from, to),
                    )?;
                }
                // The ICMPv6 checksum covers the pseudo-header.
                (IpAddr::V6(from), IpAddr::V6(to)) => {
                    icmp_checksum = checksum::update_ipv6(icmp_checksum, from, to);
                }
                _ => return None,
            }
            write_addr(packet, addr_at, outer_to)?;
        }
        write_u16(packet, checksum_at, icmp_checksum)
    }
}

/// Length of the fixed IPv6 header.
const IPV6_HEADER_LEN: usize = 40;

/// Rewrites the `to.0` address of the IP header at `ip` and port of the
/// `protocol` header at `l4` to `to.1` and `to.2`. Reads everything before
/// writing, so a `None` leaves the packet unchanged. In a `quoted` packet the
/// transport checksum may be cut off; it is updated when present.
fn rewrite_at(
    packet: &mut [u8],
    ip: usize,
    l4: usize,
    protocol: u8,
    to: (End, IpAddr, u16),
    quoted: bool,
) -> Option<()> {
    let (end, addr, port) = to;
    let addr_at = addr_offset(packet, ip, end)?;
    let old_addr = read_addr(packet, addr_at, addr.is_ipv4())?;
    let port_at = l4
        + match end {
            End::Src => 0,
            End::Dst => 2,
        };
    let old_port = read_u16(packet, port_at)?;
    let checksum_at = l4
        + match protocol {
            protocol::TCP => 16,
            protocol::UDP => 6,
            _ => return None,
        };
    let old_checksum = read_u16(packet, checksum_at);
    if old_checksum.is_none() && !quoted {
        return None;
    }
    let update = |checksum: u16| {
        let checksum = match (old_addr, addr) {
            (IpAddr::V4(old), IpAddr::V4(new)) => checksum::update_ipv4(checksum, old, new),
            (IpAddr::V6(old), IpAddr::V6(new)) => checksum::update_ipv6(checksum, old, new),
            _ => checksum,
        };
        checksum::update_u16(checksum, old_port, port)
    };
    let new_checksum = old_checksum.map(|old| {
        if protocol == protocol::UDP {
            checksum::update_udp(old, update)
        } else {
            update(old)
        }
    });
    let ip_checksum = match (old_addr, addr) {
        (IpAddr::V4(old), IpAddr::V4(new)) => {
            let at = ip + IPV4_CHECKSUM;
            Some((at, checksum::update_ipv4(read_u16(packet, at)?, old, new)))
        }
        _ => None,
    };

    write_addr(packet, addr_at, addr)?;
    write_u16(packet, port_at, port)?;
    if let Some(checksum) = new_checksum {
        write_u16(packet, checksum_at, checksum)?;
    }
    if let Some((at, checksum)) = ip_checksum {
        write_u16(packet, at, checksum)?;
    }
    Some(())
}

/// The protocol of the IP header at `ip`.
fn ip_protocol(packet: &[u8], ip: usize) -> Option<u8> {
    match packet.get(ip)? >> 4 {
        4 => packet.get(ip + 9).copied(),
        6 => packet.get(ip + 6).copied(),
        _ => None,
    }
}

/// The offset of the `end` address of the IP header at `ip`.
fn addr_offset(packet: &[u8], ip: usize, end: End) -> Option<usize> {
    let offset = match (packet.get(ip)? >> 4, end) {
        (4, End::Src) => 12,
        (4, End::Dst) => 16,
        (6, End::Src) => 8,
        (6, End::Dst) => 24,
        _ => return None,
    };
    Some(ip + offset)
}

/// The address at `at`: IPv4 when `v4`, IPv6 otherwise.
fn read_addr(packet: &[u8], at: usize, v4: bool) -> Option<IpAddr> {
    Some(if v4 {
        IpAddr::V4(Ipv4Addr::from(read::<4>(packet, at)?))
    } else {
        IpAddr::V6(Ipv6Addr::from(read::<16>(packet, at)?))
    })
}

fn write_addr(packet: &mut [u8], at: usize, addr: IpAddr) -> Option<()> {
    match addr {
        IpAddr::V4(addr) => write(packet, at, &addr.octets()),
        IpAddr::V6(addr) => write(packet, at, &addr.octets()),
    }
}

fn read<const N: usize>(packet: &[u8], at: usize) -> Option<[u8; N]> {
    packet.get(at..at.checked_add(N)?)?.try_into().ok()
}

fn read_u16(packet: &[u8], at: usize) -> Option<u16> {
    read::<2>(packet, at).map(u16::from_be_bytes)
}

fn write(packet: &mut [u8], at: usize, bytes: &[u8]) -> Option<()> {
    packet
        .get_mut(at..at.checked_add(bytes.len())?)?
        .copy_from_slice(bytes);
    Some(())
}

fn write_u16(packet: &mut [u8], at: usize, value: u16) -> Option<()> {
    write(packet, at, &value.to_be_bytes())
}
