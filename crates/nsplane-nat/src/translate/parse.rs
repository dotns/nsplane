//! Strict IPv4 and IPv6 parsing for translation.
//!
//! A packet the translator owns is checked before it is rewritten: lengths,
//! the IPv4 header checksum, IPv4 options (an unexhausted source route is
//! refused), legal addresses and the IPv6 extension header chain (a routing
//! header with segments left is refused; a fragment header ends the chain).
//! A packet quoted inside an ICMP error may be truncated and is not checked
//! for legal addresses.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Range;

use super::{Result, reasons};
use crate::checksum;

/// IPv6 next header values of the extension headers the parser knows.
pub(super) const HOP_BY_HOP: u8 = 0;
pub(super) const ROUTING: u8 = 43;
pub(super) const FRAGMENT: u8 = 44;
pub(super) const ESP: u8 = 50;
pub(super) const AH: u8 = 51;
pub(super) const NO_NEXT: u8 = 59;
pub(super) const DESTINATION_OPTIONS: u8 = 60;

/// Most extension headers accepted in one chain.
const MAX_EXTENSIONS: u8 = 16;

/// Reads a big-endian `u16` at `at`; the caller has checked the length.
pub(super) const fn be16(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}

/// Writes a big-endian `u16` at `at`; the caller has checked the length.
pub(super) fn put16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_be_bytes());
}

/// A parsed IPv4 header.
#[derive(Debug, Clone)]
pub(super) struct Ipv4 {
    pub(super) tos: u8,
    /// Total length field (bytes).
    pub(super) total_len: usize,
    pub(super) header_len: usize,
    pub(super) identification: u16,
    /// Fragment offset in 8-byte units.
    pub(super) fragment_offset: u16,
    pub(super) more_fragments: bool,
    pub(super) ttl: u8,
    pub(super) protocol: u8,
    pub(super) src: Ipv4Addr,
    pub(super) dst: Ipv4Addr,
    /// The payload bytes present in the buffer.
    pub(super) payload: Range<usize>,
}

impl Ipv4 {
    /// Parses `bytes`; `quoted` allows a truncated packet quoted in an ICMP error.
    pub(super) fn parse(bytes: &[u8], quoted: bool) -> Result<Self> {
        if bytes.len() < 20 || bytes[0] >> 4 != 4 {
            return Err(reasons::MALFORMED);
        }
        let header_len = usize::from(bytes[0] & 0x0f) * 4;
        if header_len < 20 || header_len > bytes.len() {
            return Err(reasons::MALFORMED);
        }
        let total_len = usize::from(be16(bytes, 2));
        if total_len < header_len
            || (!quoted && total_len != bytes.len())
            || (quoted && total_len < bytes.len())
        {
            return Err(reasons::LENGTH_MISMATCH);
        }
        if !checksum::valid(&bytes[..header_len]) {
            return Err(reasons::INVALID_CHECKSUM);
        }
        validate_options(&bytes[20..header_len])?;
        let src = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
        let dst = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
        if !quoted && (!legal_v4(src) || !legal_v4(dst)) {
            return Err(reasons::ILLEGAL_ADDRESS);
        }
        let fragment = be16(bytes, 6);
        if fragment & 0x8000 != 0 {
            return Err(reasons::MALFORMED);
        }
        Ok(Self {
            tos: bytes[1],
            total_len,
            header_len,
            identification: be16(bytes, 4),
            fragment_offset: fragment & 0x1fff,
            more_fragments: fragment & 0x2000 != 0,
            ttl: bytes[8],
            protocol: bytes[9],
            src,
            dst,
            payload: header_len..total_len.min(bytes.len()),
        })
    }

    /// Whether this is a fragment (first, middle or last).
    pub(super) const fn fragmented(&self) -> bool {
        self.more_fragments || self.fragment_offset != 0
    }
}

/// Checks the IPv4 option list; an unexhausted source route is refused.
fn validate_options(options: &[u8]) -> Result<()> {
    let mut cursor = 0;
    while let Some(&kind) = options.get(cursor) {
        match kind {
            0 => return Ok(()),
            1 => {
                cursor += 1;
                continue;
            }
            _ => {}
        }
        let length = options
            .get(cursor + 1)
            .copied()
            .map(usize::from)
            .ok_or(reasons::MALFORMED)?;
        if length < 2 || cursor + length > options.len() {
            return Err(reasons::MALFORMED);
        }
        // Loose (131) and strict (137) source routes.
        if kind == 131 || kind == 137 {
            if length < 3 {
                return Err(reasons::MALFORMED);
            }
            let pointer = usize::from(options[cursor + 2]);
            if pointer < 4 {
                return Err(reasons::MALFORMED);
            }
            if pointer <= length {
                return Err(reasons::SOURCE_ROUTE);
            }
        }
        cursor += length;
    }
    Ok(())
}

/// An IPv6 fragment header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Fragment {
    /// Offset in 8-byte units.
    pub(super) offset: u16,
    pub(super) more: bool,
    pub(super) identification: u32,
}

/// A parsed IPv6 header and extension header chain.
#[derive(Debug, Clone)]
pub(super) struct Ipv6 {
    pub(super) traffic_class: u8,
    /// 40 plus the payload length field (bytes).
    pub(super) total_len: usize,
    pub(super) hop_limit: u8,
    /// The upper-layer protocol after the extension headers.
    pub(super) protocol: u8,
    pub(super) src: Ipv6Addr,
    pub(super) dst: Ipv6Addr,
    /// The upper-layer bytes present in the buffer.
    pub(super) payload: Range<usize>,
    pub(super) fragment: Option<Fragment>,
}

impl Ipv6 {
    /// Parses `bytes`; `quoted` allows a truncated packet quoted in an ICMP error.
    pub(super) fn parse(bytes: &[u8], quoted: bool) -> Result<Self> {
        if bytes.len() < 40 || bytes[0] >> 4 != 6 {
            return Err(reasons::MALFORMED);
        }
        let total_len = 40 + usize::from(be16(bytes, 4));
        if (!quoted && total_len != bytes.len()) || (quoted && total_len < bytes.len()) {
            return Err(reasons::LENGTH_MISMATCH);
        }
        let src = addr6(&bytes[8..24]);
        let dst = addr6(&bytes[24..40]);
        if !quoted && (!legal_v6(src) || !legal_v6(dst)) {
            return Err(reasons::ILLEGAL_ADDRESS);
        }
        let limit = total_len.min(bytes.len());
        let (protocol, start, fragment) = walk_extensions(bytes, limit)?;
        Ok(Self {
            traffic_class: ((bytes[0] & 0x0f) << 4) | (bytes[1] >> 4),
            total_len,
            hop_limit: bytes[7],
            protocol,
            src,
            dst,
            payload: start..limit,
            fragment,
        })
    }

    /// Whether the upper-layer header is present (not a non-first fragment).
    pub(super) fn has_transport_header(&self) -> bool {
        self.fragment.is_none_or(|fragment| fragment.offset == 0)
    }
}

/// Walks the extension headers of the IPv6 packet `bytes` (whose data ends at
/// `limit`) and returns the upper-layer protocol, its offset and the fragment
/// header, if any.
fn walk_extensions(bytes: &[u8], limit: usize) -> Result<(u8, usize, Option<Fragment>)> {
    let mut next = bytes[6];
    let mut cursor = 40;
    let mut count = 0;
    loop {
        count += 1;
        if count > MAX_EXTENSIONS {
            return Err(reasons::UNSUPPORTED_EXTENSION);
        }
        match next {
            HOP_BY_HOP | DESTINATION_OPTIONS | ROUTING => {
                let length = bytes
                    .get(cursor + 1)
                    .map(|&units| (usize::from(units) + 1) * 8)
                    .ok_or(reasons::TRUNCATED)?;
                let header = bytes
                    .get(cursor..cursor + length)
                    .ok_or(reasons::TRUNCATED)?;
                if next == ROUTING && header.get(3).is_none_or(|&left| left != 0) {
                    return Err(reasons::ACTIVE_ROUTING_HEADER);
                }
                next = header[0];
                cursor += length;
            }
            FRAGMENT => {
                let header = bytes.get(cursor..cursor + 8).ok_or(reasons::TRUNCATED)?;
                next = header[0];
                if matches!(
                    next,
                    HOP_BY_HOP | ROUTING | FRAGMENT | AH | DESTINATION_OPTIONS
                ) {
                    return Err(reasons::UNSUPPORTED_EXTENSION);
                }
                let bits = be16(header, 2);
                if bits & 0x0006 != 0 {
                    return Err(reasons::MALFORMED);
                }
                let fragment = Fragment {
                    offset: bits >> 3,
                    more: bits & 1 != 0,
                    identification: u32::from_be_bytes([
                        header[4], header[5], header[6], header[7],
                    ]),
                };
                cursor += 8;
                return if cursor > limit {
                    Err(reasons::TRUNCATED)
                } else {
                    Ok((next, cursor, Some(fragment)))
                };
            }
            AH | ESP | NO_NEXT => return Err(reasons::UNSUPPORTED_PROTOCOL),
            _ => {
                return if cursor > limit {
                    Err(reasons::TRUNCATED)
                } else {
                    Ok((next, cursor, None))
                };
            }
        }
        if cursor > limit {
            return Err(reasons::TRUNCATED);
        }
    }
}

/// Reads an IPv6 address from 16 bytes.
pub(super) fn addr6(bytes: &[u8]) -> Ipv6Addr {
    let mut octets = [0; 16];
    octets.copy_from_slice(&bytes[..16]);
    Ipv6Addr::from(octets)
}

const fn legal_v4(addr: Ipv4Addr) -> bool {
    !addr.is_unspecified() && !addr.is_loopback() && !addr.is_multicast() && !addr.is_broadcast()
}

const fn legal_v6(addr: Ipv6Addr) -> bool {
    !addr.is_unspecified() && !addr.is_loopback() && !addr.is_multicast()
}
