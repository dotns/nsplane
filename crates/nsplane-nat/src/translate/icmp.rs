//! ICMP <-> `ICMPv6` translation (RFC 7915 sections 4.2, 4.3, 5.2 and 5.3).
//!
//! Echo request and reply are rewritten in place with an incremental checksum
//! update. Error messages are rebuilt: the type, code and the MTU or pointer
//! field are mapped, the quoted packet is translated in the reverse direction
//! (its addresses through the same table, its TTL kept) and the checksum is
//! recomputed (`ICMPv6` covers the IPv6 pseudo-header, ICMP does not).

use std::net::Ipv6Addr;

use nsplane_packet::protocol;

use super::parse::{Fragment, Ipv4, Ipv6, be16, put16};
use super::rfc7915::{Addrs, V4Header, V6Header, finish, update_addrs6};
use super::{Result, map4to6, map6to4, reasons};
use crate::TranslationTable;
use crate::checksum::{
    PseudoHeader, internet_checksum, transport_checksum_v6, update_pseudo_header, update_u16, valid,
};

/// IPv6 minimum MTU: the lowest MTU a translated Packet Too Big announces.
const IPV6_MIN_MTU: u32 = 1280;
/// IPv4 minimum MTU: the lowest MTU a translated fragmentation needed announces.
const IPV4_MIN_MTU: u32 = 68;
/// Header size difference between IPv6 and IPv4 (without options).
const HEADER_DIFFERENCE: u32 = 20;

/// Translates the ICMP message `body` to `ICMPv6` from `src` to `dst`.
///
/// An echo message is rewritten in place (`None`); an error message is
/// returned rebuilt.
pub(super) fn v4_to_v6(
    body: &mut [u8],
    src: Ipv6Addr,
    dst: Ipv6Addr,
    table: &TranslationTable,
) -> Result<Option<Vec<u8>>> {
    if body.len() < 8 {
        return Err(reasons::TRUNCATED);
    }
    if !valid(body) {
        return Err(reasons::INVALID_CHECKSUM);
    }
    let echo = match (body[0], body[1]) {
        (8, 0) => Some(128),
        (0, 0) => Some(129),
        _ => None,
    };
    if let Some(kind) = echo {
        let pseudo = PseudoHeader::V6 {
            src,
            dst,
            protocol: protocol::ICMPV6,
            len: u32::try_from(body.len()).map_err(|_| reasons::LENGTH_MISMATCH)?,
        };
        let old = be16(body, 0);
        body[0] = kind;
        let checksum = update_u16(be16(body, 2), old, be16(body, 0));
        put16(body, 2, update_u16(checksum, 0, pseudo.sum()));
        return Ok(None);
    }
    let (kind, code, rest) = error_v4_to_v6(body)?;
    let mut out = Vec::with_capacity(body.len() + 28);
    out.extend_from_slice(&[kind, code, 0, 0]);
    out.extend_from_slice(&rest);
    quoted_v4_to_v6(&body[8..], table, &mut out)?;
    let checksum = transport_checksum_v6(src, dst, protocol::ICMPV6, &out);
    put16(&mut out, 2, checksum);
    Ok(Some(out))
}

/// Translates the `ICMPv6` message `body` from `src` to `dst` to ICMP.
///
/// An echo message is rewritten in place (`None`); an error message is
/// returned rebuilt.
pub(super) fn v6_to_v4(
    body: &mut [u8],
    src: Ipv6Addr,
    dst: Ipv6Addr,
    table: &TranslationTable,
) -> Result<Option<Vec<u8>>> {
    if body.len() < 8 {
        return Err(reasons::TRUNCATED);
    }
    if transport_checksum_v6(src, dst, protocol::ICMPV6, body) != 0 {
        return Err(reasons::INVALID_CHECKSUM);
    }
    let echo = match (body[0], body[1]) {
        (128, 0) => Some(8),
        (129, 0) => Some(0),
        _ => None,
    };
    if let Some(kind) = echo {
        let pseudo = PseudoHeader::V6 {
            src,
            dst,
            protocol: protocol::ICMPV6,
            len: u32::try_from(body.len()).map_err(|_| reasons::LENGTH_MISMATCH)?,
        };
        let old = be16(body, 0);
        body[0] = kind;
        let checksum = update_u16(be16(body, 2), old, be16(body, 0));
        put16(body, 2, update_u16(checksum, pseudo.sum(), 0));
        return Ok(None);
    }
    let (kind, code, rest) = error_v6_to_v4(body)?;
    let mut out = Vec::with_capacity(body.len());
    out.extend_from_slice(&[kind, code, 0, 0]);
    out.extend_from_slice(&rest);
    quoted_v6_to_v4(&body[8..], table, &mut out)?;
    let checksum = internet_checksum(&out);
    put16(&mut out, 2, checksum);
    Ok(Some(out))
}

/// Maps an ICMP error's type, code and second word to `ICMPv6`.
fn error_v4_to_v6(body: &[u8]) -> Result<(u8, u8, [u8; 4])> {
    let rest = [body[4], body[5], body[6], body[7]];
    Ok(match (body[0], body[1]) {
        // Net, host, source route failed, network/host unknown, source host
        // isolated, TOS unreachable: no route.
        (3, 0 | 1 | 5 | 6 | 7 | 8 | 11 | 12) => (1, 0, rest),
        // Protocol unreachable: parameter problem, unrecognized next header,
        // pointing at the next header field.
        (3, 2) => (4, 1, 6_u32.to_be_bytes()),
        // Port unreachable.
        (3, 3) => (1, 4, rest),
        // Fragmentation needed: Packet Too Big, MTU grown by the header difference.
        (3, 4) => {
            let mtu = (u32::from(be16(body, 6)) + HEADER_DIFFERENCE).max(IPV6_MIN_MTU);
            (2, 0, mtu.to_be_bytes())
        }
        // Administratively prohibited.
        (3, 9 | 10 | 13 | 15) => (1, 1, rest),
        // Time exceeded (hop limit, reassembly).
        (11, code @ (0 | 1)) => (3, code, rest),
        // Parameter problem: erroneous header field, pointer mapped.
        (12, 0 | 2) => (4, 0, pointer_v4_to_v6(body[4])?.to_be_bytes()),
        _ => return Err(reasons::UNSUPPORTED_ICMP),
    })
}

/// Maps an `ICMPv6` error's type, code and second word to ICMP.
fn error_v6_to_v4(body: &[u8]) -> Result<(u8, u8, [u8; 4])> {
    let rest = [body[4], body[5], body[6], body[7]];
    Ok(match (body[0], body[1]) {
        // No route, beyond scope, address unreachable: host unreachable.
        (1, 0 | 2 | 3) => (3, 1, rest),
        // Administratively prohibited.
        (1, 1) => (3, 10, rest),
        // Port unreachable.
        (1, 4) => (3, 3, rest),
        // Packet Too Big: fragmentation needed, MTU shrunk by the header difference.
        (2, 0) => {
            let mtu = u32::from_be_bytes(rest)
                .saturating_sub(HEADER_DIFFERENCE)
                .max(IPV4_MIN_MTU);
            let [hi, lo] = u16::try_from(mtu).unwrap_or(u16::MAX).to_be_bytes();
            (3, 4, [0, 0, hi, lo])
        }
        // Time exceeded (hop limit, reassembly).
        (3, code @ (0 | 1)) => (11, code, rest),
        // Unrecognized next header: protocol unreachable.
        (4, 1) => (3, 2, [0; 4]),
        // Erroneous header field: parameter problem, pointer mapped.
        (4, 0) => (
            12,
            0,
            [pointer_v6_to_v4(u32::from_be_bytes(rest))?, 0, 0, 0],
        ),
        _ => return Err(reasons::UNSUPPORTED_ICMP),
    })
}

/// Translates the IPv4 packet quoted in an ICMP error and appends it to `out`.
fn quoted_v4_to_v6(bytes: &[u8], table: &TranslationTable, out: &mut Vec<u8>) -> Result<()> {
    let inner = Ipv4::parse(bytes, true)?;
    if inner.protocol == protocol::ICMP
        && bytes
            .get(inner.payload.start)
            .is_some_and(|kind| matches!(kind, 3 | 4 | 5 | 11 | 12))
    {
        return Err(reasons::UNSUPPORTED_ICMP);
    }
    let addrs = Addrs {
        src4: inner.src,
        dst4: inner.dst,
        src6: map4to6(table, inner.src).ok_or(reasons::UNMAPPED)?,
        dst6: map4to6(table, inner.dst).ok_or(reasons::UNMAPPED)?,
    };
    let upper_len = inner.total_len - inner.header_len;
    let (header, header_len) = V6Header {
        traffic_class: inner.tos,
        upper_len,
        protocol: if inner.protocol == protocol::ICMP {
            protocol::ICMPV6
        } else {
            inner.protocol
        },
        hop_limit: inner.ttl,
        src: addrs.src6,
        dst: addrs.dst6,
        fragment: inner.fragmented().then_some(Fragment {
            offset: inner.fragment_offset,
            more: inner.more_fragments,
            identification: u32::from(inner.identification),
        }),
    }
    .encode()?;
    out.extend_from_slice(&header[..header_len]);
    let start = out.len();
    out.extend_from_slice(&bytes[inner.payload.clone()]);
    if inner.fragment_offset == 0 {
        quoted_transport(&mut out[start..], inner.protocol, addrs, upper_len, true)?;
    }
    Ok(())
}

/// Translates the IPv6 packet quoted in an `ICMPv6` error and appends it to `out`.
fn quoted_v6_to_v4(bytes: &[u8], table: &TranslationTable, out: &mut Vec<u8>) -> Result<()> {
    let inner = Ipv6::parse(bytes, true)?;
    if inner.protocol == protocol::ICMPV6
        && bytes
            .get(inner.payload.start)
            .is_some_and(|&kind| kind < 128)
    {
        return Err(reasons::UNSUPPORTED_ICMP);
    }
    let addrs = Addrs {
        src4: map6to4(table, inner.src).ok_or(reasons::UNMAPPED)?,
        dst4: map6to4(table, inner.dst).ok_or(reasons::UNMAPPED)?,
        src6: inner.src,
        dst6: inner.dst,
    };
    let upper_len = inner.total_len - inner.payload.start;
    let header = V4Header {
        tos: inner.traffic_class,
        upper_len,
        ttl: inner.hop_limit,
        protocol: if inner.protocol == protocol::ICMPV6 {
            protocol::ICMP
        } else {
            inner.protocol
        },
        src: addrs.src4,
        dst: addrs.dst4,
        fragment: inner.fragment,
        dont_fragment: true,
    }
    .encode()?;
    out.extend_from_slice(&header);
    let start = out.len();
    out.extend_from_slice(&bytes[inner.payload.clone()]);
    if inner.has_transport_header() {
        quoted_transport(&mut out[start..], inner.protocol, addrs, upper_len, false)?;
    }
    Ok(())
}

/// Moves the checksum of a quoted (possibly truncated) TCP, UDP or echo
/// header to the other family; `to_v6` gives the direction and `upper_len`
/// the quoted packet's upper-layer length.
fn quoted_transport(
    segment: &mut [u8],
    protocol: u8,
    addrs: Addrs,
    upper_len: usize,
    to_v6: bool,
) -> Result<()> {
    let (old, new) = if to_v6 {
        (addrs.v4(protocol), addrs.v6(protocol))
    } else {
        (addrs.v6(protocol), addrs.v4(protocol))
    };
    match protocol {
        protocol::TCP | protocol::UDP => {
            let at = if protocol == protocol::TCP { 16 } else { 6 };
            if segment.len() < at + 2 {
                return Ok(());
            }
            let checksum = be16(segment, at);
            if checksum == 0 {
                // IPv4 UDP without a checksum stays without one; zero is
                // invalid over IPv6.
                return if to_v6 && protocol == protocol::UDP {
                    Ok(())
                } else {
                    Err(reasons::INVALID_CHECKSUM)
                };
            }
            put16(
                segment,
                at,
                finish(protocol, update_pseudo_header(checksum, old, new)),
            );
        }
        protocol::ICMP | protocol::ICMPV6 if segment.len() >= 4 => {
            let kind = match (to_v6, segment[0]) {
                (true, 8) => 128,
                (true, 0) => 129,
                (false, 128) => 8,
                (false, 129) => 0,
                _ => return Ok(()),
            };
            let pseudo = PseudoHeader::V6 {
                src: addrs.src6,
                dst: addrs.dst6,
                protocol: protocol::ICMPV6,
                len: u32::try_from(upper_len).map_err(|_| reasons::LENGTH_MISMATCH)?,
            }
            .sum();
            let old = be16(segment, 0);
            segment[0] = kind;
            let checksum = update_u16(be16(segment, 2), old, be16(segment, 0));
            let checksum = if to_v6 {
                update_u16(checksum, 0, pseudo)
            } else {
                update_u16(checksum, pseudo, 0)
            };
            put16(segment, 2, checksum);
        }
        _ => {}
    }
    Ok(())
}

/// Rewrites the addresses of the IPv6 packet quoted in an `ICMPv6` error
/// through `map` (unmapped addresses stay) and returns the ICMP `checksum`
/// updated for the changed bytes. An unparsable quote is left alone.
pub(super) fn rewrite_quoted_v6(
    quote: &mut [u8],
    checksum: u16,
    map: &dyn Fn(Ipv6Addr) -> Option<Ipv6Addr>,
) -> u16 {
    let Ok(inner) = Ipv6::parse(quote, true) else {
        return checksum;
    };
    let src = map(inner.src).unwrap_or(inner.src);
    let dst = map(inner.dst).unwrap_or(inner.dst);
    if (src, dst) == (inner.src, inner.dst) {
        return checksum;
    }
    let old = (inner.src, inner.dst);
    let checksum = update_addrs6(checksum, old, (src, dst));
    quote[8..24].copy_from_slice(&src.octets());
    quote[24..40].copy_from_slice(&dst.octets());
    if !inner.has_transport_header() {
        return checksum;
    }
    let segment = &quote[inner.payload.clone()];
    let at = match inner.protocol {
        protocol::TCP if segment.len() >= 18 => 16,
        protocol::UDP if segment.len() >= 8 => 6,
        protocol::ICMPV6 if segment.len() >= 4 => 2,
        _ => return checksum,
    };
    let at = inner.payload.start + at;
    let field = be16(quote, at);
    let updated = if inner.protocol == protocol::UDP && field == 0 {
        0
    } else {
        finish(inner.protocol, update_addrs6(field, old, (src, dst)))
    };
    put16(quote, at, updated);
    update_u16(checksum, field, updated)
}

/// Maps an ICMP parameter problem pointer to `ICMPv6` (RFC 7915 section 4.2).
const fn pointer_v4_to_v6(pointer: u8) -> Result<u32> {
    match pointer {
        0 => Ok(0),
        1 => Ok(1),
        2 | 3 => Ok(4),
        8 => Ok(7),
        9 => Ok(6),
        12..=15 => Ok(8),
        16..=19 => Ok(24),
        _ => Err(reasons::UNSUPPORTED_ICMP),
    }
}

/// Maps an `ICMPv6` parameter problem pointer to ICMP (RFC 7915 section 5.2).
const fn pointer_v6_to_v4(pointer: u32) -> Result<u8> {
    match pointer {
        0 => Ok(0),
        1 => Ok(1),
        4 | 5 => Ok(2),
        6 => Ok(9),
        7 => Ok(8),
        8..=23 => Ok(12),
        24..=39 => Ok(16),
        _ => Err(reasons::UNSUPPORTED_ICMP),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointer_maps_follow_rfc7915() {
        let v4 = [
            (0, 0),
            (1, 1),
            (2, 4),
            (3, 4),
            (8, 7),
            (9, 6),
            (12, 8),
            (16, 24),
        ];
        for (four, six) in v4 {
            assert_eq!(pointer_v4_to_v6(four), Ok(six));
        }
        assert_eq!(pointer_v4_to_v6(10), Err(reasons::UNSUPPORTED_ICMP));
        let v6 = [
            (0, 0),
            (1, 1),
            (4, 2),
            (6, 9),
            (7, 8),
            (8, 12),
            (24, 16),
            (39, 16),
        ];
        for (six, four) in v6 {
            assert_eq!(pointer_v6_to_v4(six), Ok(four));
        }
        assert_eq!(pointer_v6_to_v4(2), Err(reasons::UNSUPPORTED_ICMP));
        assert_eq!(pointer_v6_to_v4(40), Err(reasons::UNSUPPORTED_ICMP));
    }

    #[test]
    fn packet_too_big_mtu_is_bounded() {
        for (advertised, expected) in [
            (0_u32, 68_u16),
            (1279, 1259),
            (1300, 1280),
            (u32::MAX, u16::MAX),
        ] {
            let mut body = [2, 0, 0, 0, 0, 0, 0, 0];
            body[4..8].copy_from_slice(&advertised.to_be_bytes());
            let (kind, code, rest) = error_v6_to_v4(&body).unwrap();
            assert_eq!((kind, code), (3, 4));
            assert_eq!(u16::from_be_bytes([rest[2], rest[3]]), expected);
        }
        for (next_hop, expected) in [(0_u16, 1280_u32), (1400, 1420), (1500, 1520)] {
            let mut body = [3, 4, 0, 0, 0, 0, 0, 0];
            body[6..8].copy_from_slice(&next_hop.to_be_bytes());
            let (kind, code, rest) = error_v4_to_v6(&body).unwrap();
            assert_eq!((kind, code), (2, 0));
            assert_eq!(u32::from_be_bytes(rest), expected);
        }
    }
}
