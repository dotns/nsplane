//! A walker over the IPv6 extension header chain.
//!
//! [`ExtensionWalker`] steps over one extension header at a time and holds no policy:
//! how many headers a chain may have, which kinds are refused and what a cut chain means
//! are the caller's decisions, taken between steps from [`ExtensionWalker::next_header`].
//! It borrows the packet, never allocates and never panics.

use crate::Malformed;
use crate::protocol::{AH, IPV6_DESTINATION_OPTIONS, IPV6_FRAGMENT, IPV6_HOP_BY_HOP, IPV6_ROUTING};

/// Length of the IPv6 Fragment header.
const FRAGMENT_HEADER_LEN: usize = 8;

/// The fields of an IPv6 Fragment header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv6Fragment {
    /// Fragment identification.
    pub id: u32,
    /// Offset of this fragment's data in bytes, a multiple of 8.
    pub offset: u16,
    /// Whether more fragments follow.
    pub more: bool,
}

impl Ipv6Fragment {
    /// Whether this is the first fragment (offset 0).
    pub const fn is_first(&self) -> bool {
        self.offset == 0
    }

    /// Whether this is the last fragment (more-fragments clear).
    pub const fn is_last(&self) -> bool {
        !self.more
    }
}

/// One extension header of a chain, from [`ExtensionWalker::step`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtensionHeader<'a> {
    kind: u8,
    offset: usize,
    bytes: &'a [u8],
}

impl<'a> ExtensionHeader<'a> {
    /// The next-header value that announced this header: which extension header it is.
    pub const fn kind(&self) -> u8 {
        self.kind
    }

    /// Where the header starts in the walked bytes.
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// The whole header, at least 8 bytes.
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The fields of a Fragment header; `None` for another kind. The two reserved bits
    /// next to the M flag are not checked: they are bits 1 and 2 of byte 3 of
    /// [`bytes`](Self::bytes).
    #[inline]
    pub const fn fragment(&self) -> Option<Ipv6Fragment> {
        if self.kind != IPV6_FRAGMENT {
            return None;
        }
        let &[_, _, hi, lo, id0, id1, id2, id3] = self.bytes else {
            return None;
        };
        let field = u16::from_be_bytes([hi, lo]);
        Some(Ipv6Fragment {
            id: u32::from_be_bytes([id0, id1, id2, id3]),
            offset: field & !7,
            more: field & 1 != 0,
        })
    }
}

/// A cursor over the extension headers of an IPv6 packet.
///
/// [`step`](Self::step) moves past one header: Hop-by-Hop Options, Routing and
/// Destination Options by their length field (8-byte units beyond the first 8 bytes),
/// an Authentication Header by its own (4-byte units beyond the first 8 bytes) and a
/// Fragment header (8 bytes). Every other next-header value, ESP and No Next Header
/// included, ends the chain: `step` returns `Ok(None)`, [`next_header`](Self::next_header)
/// is the upper-layer protocol and [`offset`](Self::offset) is where it starts.
///
/// The walker has no limits and no policy of its own. A caller that refuses a kind, or
/// treats it as the upper layer, tests `next_header` before it steps; a caller bounding
/// the chain counts its steps. The data of a fragment with a non-zero offset starts in
/// the middle of the fragmented datagram, so a caller stops stepping after such a
/// Fragment header: `next_header` then names what the first fragment carries.
///
/// ```
/// use nsplane_packet::{ExtensionWalker, protocol};
///
/// // A Destination Options header, then UDP.
/// let payload = [protocol::UDP, 0, 1, 4, 0, 0, 0, 0, 0xca, 0x6c, 0x00, 0x35];
/// let mut walker = ExtensionWalker::new(&payload, protocol::IPV6_DESTINATION_OPTIONS, 0);
/// let mut headers = 0;
/// while let Some(header) = walker.step()? {
///     assert_eq!(header.kind(), protocol::IPV6_DESTINATION_OPTIONS);
///     headers += 1;
/// }
/// assert_eq!((headers, walker.next_header(), walker.offset()), (1, protocol::UDP, 8));
/// # Ok::<(), nsplane_packet::Malformed>(())
/// ```
#[derive(Debug, Clone, Copy)]
pub struct ExtensionWalker<'a> {
    bytes: &'a [u8],
    next_header: u8,
    offset: usize,
}

impl<'a> ExtensionWalker<'a> {
    /// A walker over `bytes`, whose header announced by `next_header` starts at `offset`:
    /// for a whole packet the fixed header's next header and 40, for its payload 0. The
    /// chain ends where `bytes` ends, so `bytes` is cut at the payload length first if
    /// bytes behind it must not count.
    #[inline]
    pub const fn new(bytes: &'a [u8], next_header: u8, offset: usize) -> Self {
        Self {
            bytes,
            next_header,
            offset,
        }
    }

    /// The next-header value at the cursor: the kind of the header the next
    /// [`step`](Self::step) reads, or the upper-layer protocol once it returned `Ok(None)`.
    #[inline]
    pub const fn next_header(&self) -> u8 {
        self.next_header
    }

    /// The cursor: where the header or upper layer named by
    /// [`next_header`](Self::next_header) starts. At most the length of the walked bytes
    /// after a step that returned a header.
    #[inline]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// Whether [`next_header`](Self::next_header) is a kind [`step`](Self::step) moves
    /// past.
    #[inline]
    pub const fn at_extension(&self) -> bool {
        matches!(
            self.next_header,
            IPV6_HOP_BY_HOP | IPV6_ROUTING | IPV6_DESTINATION_OPTIONS | AH | IPV6_FRAGMENT
        )
    }

    /// Moves past the extension header at the cursor and returns it, or returns `Ok(None)`
    /// and stays when the cursor is at the upper layer. A header that does not lie whole
    /// within the bytes is [`Malformed::Truncated`]; the cursor stays on it.
    #[inline]
    pub fn step(&mut self) -> Result<Option<ExtensionHeader<'a>>, Malformed> {
        let kind = self.next_header;
        if !self.at_extension() {
            return Ok(None);
        }
        let rest = self.bytes.get(self.offset..).ok_or(Malformed::Truncated)?;
        let field = |rest: &[u8]| rest.get(1).map(|&field| usize::from(field));
        let length = match kind {
            IPV6_FRAGMENT => FRAGMENT_HEADER_LEN,
            AH => (field(rest).ok_or(Malformed::Truncated)? + 2) * 4,
            _ => (field(rest).ok_or(Malformed::Truncated)? + 1) * 8,
        };
        let bytes = rest.get(..length).ok_or(Malformed::Truncated)?;
        let header = ExtensionHeader {
            kind,
            offset: self.offset,
            bytes,
        };
        self.next_header = *bytes.first().ok_or(Malformed::Truncated)?;
        self.offset += length;
        Ok(Some(header))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{TCP, UDP};

    /// A Hop-by-Hop, Routing or Destination Options header of `units` 8-byte units
    /// followed by `next`.
    fn options(next: u8, units: u8) -> Vec<u8> {
        let mut header = vec![0xee_u8; usize::from(units) * 8];
        header[..2].copy_from_slice(&[next, units - 1]);
        header
    }

    /// An Authentication Header with length field `field` followed by `next`.
    fn ah(next: u8, field: u8) -> Vec<u8> {
        let mut header = vec![0xaa_u8; (usize::from(field) + 2) * 4];
        header[..2].copy_from_slice(&[next, field]);
        header
    }

    fn fragment(next: u8, field: u16, id: u32) -> Vec<u8> {
        let mut header = vec![next, 0];
        header.extend_from_slice(&field.to_be_bytes());
        header.extend_from_slice(&id.to_be_bytes());
        header
    }

    /// Steps to the end of the chain: the kinds, offsets and lengths of its headers.
    fn walk(walker: &mut ExtensionWalker<'_>) -> Result<Vec<(u8, usize, usize)>, Malformed> {
        let mut headers = Vec::new();
        while let Some(header) = walker.step()? {
            headers.push((header.kind(), header.offset(), header.bytes().len()));
        }
        Ok(headers)
    }

    #[test]
    fn no_extension_header() {
        for next in [TCP, UDP, 50, 58, 59, 135, 139, 140, 253, 255] {
            for bytes in [&[][..], &[0, 9, 0, 0]] {
                let mut walker = ExtensionWalker::new(bytes, next, 0);
                assert!(!walker.at_extension());
                assert_eq!(walker.step(), Ok(None), "next header {next}");
                assert_eq!((walker.next_header(), walker.offset()), (next, 0));
            }
        }
        // The upper layer is not looked at, even where the cursor is past the bytes.
        let mut walker = ExtensionWalker::new(&[], UDP, 40);
        assert_eq!(walker.step(), Ok(None));
        assert_eq!(walker.offset(), 40);
    }

    #[test]
    fn every_kind_is_stepped_over_by_its_length() {
        let chain = [
            options(IPV6_DESTINATION_OPTIONS, 1),
            options(IPV6_ROUTING, 2),
            options(AH, 3),
            ah(IPV6_FRAGMENT, 4),
            fragment(IPV6_DESTINATION_OPTIONS, 1, 7),
            options(TCP, 255),
            vec![1, 2, 3],
        ]
        .concat();
        // The same chain as a payload and behind 40 bytes of fixed header.
        for base in [0, 40] {
            let bytes = [vec![0xff; base], chain.clone()].concat();
            let mut walker = ExtensionWalker::new(&bytes, IPV6_HOP_BY_HOP, base);
            assert!(walker.at_extension());
            assert_eq!(
                walk(&mut walker),
                Ok(vec![
                    (IPV6_HOP_BY_HOP, base, 8),
                    (IPV6_DESTINATION_OPTIONS, base + 8, 16),
                    (IPV6_ROUTING, base + 24, 24),
                    (AH, base + 48, 24),
                    (IPV6_FRAGMENT, base + 72, 8),
                    (IPV6_DESTINATION_OPTIONS, base + 80, 2040),
                ])
            );
            assert_eq!((walker.next_header(), walker.offset()), (TCP, base + 2120));
            assert_eq!(&bytes[walker.offset()..], [1, 2, 3]);
            // Stepping again stays at the upper layer.
            assert_eq!(walker.step(), Ok(None));
            assert_eq!(walker.offset(), base + 2120);
        }
    }

    #[test]
    fn length_fields_at_their_bounds() {
        for (kind, field, length) in [
            (IPV6_HOP_BY_HOP, 0, 8),
            (IPV6_ROUTING, 0, 8),
            (IPV6_DESTINATION_OPTIONS, 0, 8),
            (IPV6_DESTINATION_OPTIONS, 255, 2048),
            (AH, 0, 8),
            (AH, 1, 12),
            (AH, 255, 1028),
        ] {
            let mut bytes = vec![0_u8; length];
            bytes[..2].copy_from_slice(&[UDP, field]);
            // The upper layer may be empty: the chain ends where the bytes end.
            let mut walker = ExtensionWalker::new(&bytes, kind, 0);
            let header = walker.step().unwrap().unwrap();
            assert_eq!((header.kind(), header.bytes().len()), (kind, length));
            assert_eq!((walker.next_header(), walker.offset()), (UDP, length));
            assert_eq!(walker.step(), Ok(None));
            // One byte short.
            let mut walker = ExtensionWalker::new(&bytes[..length - 1], kind, 0);
            assert_eq!(walker.step(), Err(Malformed::Truncated), "kind {kind}");
            assert_eq!((walker.next_header(), walker.offset()), (kind, 0));
        }
    }

    #[test]
    fn a_cut_header_is_truncated_and_the_cursor_stays() {
        let whole = [options(IPV6_FRAGMENT, 1), fragment(UDP, 0, 1)].concat();
        for (kind, bytes, offset) in [
            (IPV6_HOP_BY_HOP, &[][..], 0),
            (IPV6_HOP_BY_HOP, &[UDP][..], 0),
            (AH, &[UDP][..], 0),
            (AH, &[UDP, 1, 0, 0, 0, 0, 0, 0][..], 0),
            (IPV6_FRAGMENT, &[][..], 0),
            (IPV6_FRAGMENT, &whole[8..15], 0),
            (IPV6_ROUTING, &[UDP, 1, 0, 0, 0, 0, 0, 0][..], 0),
            // The cursor at and past the end of the bytes.
            (IPV6_DESTINATION_OPTIONS, &whole[..], 16),
            (IPV6_DESTINATION_OPTIONS, &whole[..], 17),
            (IPV6_FRAGMENT, &whole[..], usize::MAX),
            (IPV6_HOP_BY_HOP, &whole[..], usize::MAX),
        ] {
            let mut walker = ExtensionWalker::new(bytes, kind, offset);
            assert_eq!(walker.step(), Err(Malformed::Truncated), "kind {kind}");
            assert_eq!((walker.next_header(), walker.offset()), (kind, offset));
            assert_eq!(walker.step(), Err(Malformed::Truncated), "again");
        }
        // A whole header, then a cut one.
        let mut walker = ExtensionWalker::new(&whole[..15], IPV6_HOP_BY_HOP, 0);
        assert!(walker.step().unwrap().is_some());
        assert_eq!(walker.step(), Err(Malformed::Truncated));
        assert_eq!((walker.next_header(), walker.offset()), (IPV6_FRAGMENT, 8));
    }

    #[test]
    fn fragment_fields() {
        for (field, offset, more) in [
            (0, 0, false),
            (1, 0, true),
            ((5 << 3) | 1, 40, true),
            (0xfff8, 0xfff8, false),
            // The reserved bits are neither reported nor refused.
            (0xfffe, 0xfff8, false),
            (0b111, 0, true),
        ] {
            let bytes = fragment(UDP, field, 0x0102_0304);
            let mut walker = ExtensionWalker::new(&bytes, IPV6_FRAGMENT, 0);
            let header = walker.step().unwrap().unwrap();
            let found = header.fragment().unwrap();
            assert_eq!(
                found,
                Ipv6Fragment {
                    id: 0x0102_0304,
                    offset,
                    more
                }
            );
            assert_eq!(found.is_first(), offset == 0);
            assert_eq!(found.is_last(), !more);
            assert_eq!(header.bytes(), bytes);
            assert_eq!((walker.next_header(), walker.offset()), (UDP, 8));
        }
        let bytes = options(UDP, 1);
        for kind in [IPV6_HOP_BY_HOP, IPV6_ROUTING, IPV6_DESTINATION_OPTIONS, AH] {
            let mut walker = ExtensionWalker::new(&bytes, kind, 0);
            assert_eq!(walker.step().unwrap().unwrap().fragment(), None);
        }
    }

    #[test]
    fn the_walker_has_no_limit_and_no_fragment_policy() {
        // 500 one-unit headers, two Fragment headers among them.
        let mut bytes = Vec::new();
        for index in 0..500 {
            let next = match index {
                99 | 299 => IPV6_FRAGMENT,
                499 => UDP,
                _ => IPV6_DESTINATION_OPTIONS,
            };
            if matches!(index, 100 | 300) {
                bytes.extend_from_slice(&fragment(next, 8, 1));
            } else {
                bytes.extend_from_slice(&options(next, 1));
            }
        }
        let mut walker = ExtensionWalker::new(&bytes, IPV6_HOP_BY_HOP, 0);
        let headers = walk(&mut walker).unwrap();
        assert_eq!(headers.len(), 500);
        assert_eq!((walker.next_header(), walker.offset()), (UDP, 4000));
        assert_eq!(headers.iter().filter(|h| h.0 == IPV6_FRAGMENT).count(), 2);
    }

    #[test]
    fn a_caller_chooses_what_ends_its_chain() {
        // Authentication Headers as the upper layer: test before stepping.
        let bytes = [options(AH, 1), ah(UDP, 1)].concat();
        let mut walker = ExtensionWalker::new(&bytes, IPV6_HOP_BY_HOP, 0);
        while walker.next_header() != AH && walker.step().unwrap().is_some() {}
        assert_eq!((walker.next_header(), walker.offset()), (AH, 8));
        // A copy walks on without moving the original.
        let mut copy = walker;
        assert_eq!(walk(&mut copy), Ok(vec![(AH, 8, 12)]));
        assert_eq!(walker.offset(), 8);
        assert_eq!((copy.next_header(), copy.offset()), (UDP, 20));
    }
}
