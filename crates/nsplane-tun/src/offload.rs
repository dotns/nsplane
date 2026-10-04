//! Virtio-net offload codec for the Linux TUN `IFF_VNET_HDR` mode; pure, no I/O.
//!
//! With `IFF_VNET_HDR` every packet crossing the TUN fd is preceded by a
//! [`VirtioNetHdr`]. Reads may then yield one TCP or UDP super-packet (GSO) that
//! [`segment`] splits into MTU-sized IP packets; writes may carry one super-packet that
//! the kernel splits again (GRO toward the kernel), which [`Coalescer`] builds from runs
//! of packets of the same flow.
//!
//! Checksums are computed here rather than with `nsplane-packet`'s helpers: the codec
//! needs the folded, uncomplemented partial sums the kernel works with, which those
//! helpers do not expose.

use std::iter;

use nsplane::{MAX_BATCH, PacketBatch, PacketBuf, PacketPool, TAILROOM};

/// Length of an IPv4 header without options.
const IPV4_HDR: usize = 20;
/// Length of the fixed IPv6 header.
const IPV6_HDR: usize = 40;
/// Length of a TCP header without options.
const TCP_HDR: usize = 20;
/// Length of a UDP header.
const UDP_HDR: usize = 8;
/// IP protocol number of TCP.
const TCP: u8 = 6;
/// IP protocol number of UDP.
const UDP: u8 = 17;
/// TCP flag bits.
const TCP_FIN: u8 = 0x01;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;
const TCP_CWR: u8 = 0x80;
/// Offset of the checksum field inside the TCP header.
const TCP_CSUM_OFFSET: usize = 16;
/// Offset of the checksum field inside the UDP header.
const UDP_CSUM_OFFSET: usize = 6;
/// Largest IP packet (and so largest super-packet) the codec produces.
const MAX_IP_LEN: usize = 65535;
/// Most packets one super-packet built by [`Coalescer`] carries, so that
/// [`segment`] can always split it into a single batch.
const MAX_SEGMENTS: usize = MAX_BATCH;

/// `struct virtio_net_hdr` as the legacy TUN vnet header carries it: 10 bytes, every
/// 16-bit field in host byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct VirtioNetHdr {
    /// [`Self::F_NEEDS_CSUM`] or 0.
    pub(crate) flags: u8,
    /// One of the `GSO_*` types, optionally or-ed with [`Self::GSO_ECN`].
    pub(crate) gso_type: u8,
    /// Length of the IP and transport headers of a super-packet.
    pub(crate) hdr_len: u16,
    /// Transport payload bytes per segment.
    pub(crate) gso_size: u16,
    /// Offset of the transport header, where checksumming starts.
    pub(crate) csum_start: u16,
    /// Offset of the checksum field from `csum_start`.
    pub(crate) csum_offset: u16,
}

impl VirtioNetHdr {
    /// Encoded length in bytes.
    pub(crate) const LEN: usize = 10;
    /// The checksum at `csum_start + csum_offset` holds the pseudo-header sum only and
    /// must be completed over the bytes from `csum_start` to the end.
    pub(crate) const F_NEEDS_CSUM: u8 = 1;
    /// Not a super-packet.
    pub(crate) const GSO_NONE: u8 = 0;
    /// TCP over IPv4 super-packet.
    pub(crate) const GSO_TCPV4: u8 = 1;
    /// TCP over IPv6 super-packet.
    pub(crate) const GSO_TCPV6: u8 = 4;
    /// UDP super-packet (USO), IPv4 or IPv6.
    pub(crate) const GSO_UDP_L4: u8 = 5;
    /// Flag bit: the TCP super-packet has CWR set (on its first segment only).
    pub(crate) const GSO_ECN: u8 = 0x80;

    /// Parses the first [`Self::LEN`] bytes of `bytes`.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, OffloadError> {
        let b = bytes
            .first_chunk::<{ Self::LEN }>()
            .ok_or(OffloadError::Truncated)?;
        Ok(Self {
            flags: b[0],
            gso_type: b[1],
            hdr_len: u16::from_ne_bytes([b[2], b[3]]),
            gso_size: u16::from_ne_bytes([b[4], b[5]]),
            csum_start: u16::from_ne_bytes([b[6], b[7]]),
            csum_offset: u16::from_ne_bytes([b[8], b[9]]),
        })
    }

    /// The header as written in front of a packet.
    pub(crate) fn encode(&self) -> [u8; Self::LEN] {
        let mut b = [0; Self::LEN];
        b[0] = self.flags;
        b[1] = self.gso_type;
        b[2..4].copy_from_slice(&self.hdr_len.to_ne_bytes());
        b[4..6].copy_from_slice(&self.gso_size.to_ne_bytes());
        b[6..8].copy_from_slice(&self.csum_start.to_ne_bytes());
        b[8..10].copy_from_slice(&self.csum_offset.to_ne_bytes());
        b
    }
}

/// Why a header or packet was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OffloadError {
    /// The input is shorter than the headers it must hold (including `hdr_len`).
    Truncated,
    /// The `gso_type` is unknown or unsupported (e.g. UFO, or ECN on UDP).
    UnsupportedGso,
    /// A GSO type with `gso_size` 0.
    ZeroGsoSize,
    /// The IP or transport header does not match the GSO type: wrong version or
    /// protocol, bad IHL or data offset, IPv6 extension headers, or a fragment.
    BadHeaders,
    /// `csum_start + csum_offset` leaves no room for a 16-bit checksum.
    BadChecksumOffset,
    /// A segment would exceed [`MAX_IP_LEN`] bytes.
    TooLong,
}

/// Splits one packet read from the TUN fd, preceded by `hdr`, into IP packets.
///
/// `GSO_NONE` yields the packet itself (with its checksum completed if
/// [`VirtioNetHdr::F_NEEDS_CSUM`] is set). TCP and UDP super-packets yield one packet per
/// `gso_size` bytes of payload (the last may be shorter), each with its own lengths,
/// IPv4 identification (+1 per segment) and header checksum, TCP sequence number and
/// flags (FIN and PSH only on the last segment, CWR only on the first) and a full
/// transport checksum. The header length is taken from the packet (IP header plus TCP
/// data offset or UDP header), not from `hdr_len` or `csum_start`; IPv6 extension
/// headers are not supported.
///
/// Every packet is taken from `pool` with the standard headroom and a capacity of at
/// least `capacity` (or its length plus [`TAILROOM`], if larger, so it is sealed in
/// place), and appended to `out`, starting at segment index `first`. Segments that do not
/// fit into `out` (at most [`MAX_BATCH`] packets) are not produced: the call then returns
/// `Ok(Some(next))` and the caller continues with `first = next` and a batch with room.
/// `Ok(None)` means all segments were produced. A malformed header or packet is an error
/// and produces nothing.
pub(crate) fn segment(
    hdr: &VirtioNetHdr,
    packet: &[u8],
    first: usize,
    capacity: usize,
    pool: &mut PacketPool,
    out: &mut PacketBatch,
) -> Result<Option<usize>, OffloadError> {
    let gso = hdr.gso_type & !VirtioNetHdr::GSO_ECN;
    if gso == VirtioNetHdr::GSO_NONE {
        if hdr.gso_type != gso {
            return Err(OffloadError::UnsupportedGso);
        }
        let csum = if hdr.flags & VirtioNetHdr::F_NEEDS_CSUM == 0 {
            None
        } else {
            let start = usize::from(hdr.csum_start);
            let field = start + usize::from(hdr.csum_offset);
            if field + 2 > packet.len() {
                return Err(OffloadError::BadChecksumOffset);
            }
            Some((start, field))
        };
        if first > 0 {
            return Ok(None);
        }
        let mut buf = pool.get((packet.len() + TAILROOM).max(capacity));
        buf.extend_from_slice(packet);
        let seg = buf.as_packet_mut();
        if let Some((start, field)) = csum {
            let mut csum = !fold(sum(0, &seg[start..]));
            if csum == 0 && l4_protocol(seg) == Some(UDP) {
                csum = 0xFFFF;
            }
            seg[field..field + 2].copy_from_slice(&csum.to_be_bytes());
        }
        return Ok(push(out, pool, buf, 0));
    }

    let (version, proto) = match gso {
        VirtioNetHdr::GSO_TCPV4 => (4, TCP),
        VirtioNetHdr::GSO_TCPV6 => (6, TCP),
        VirtioNetHdr::GSO_UDP_L4 if hdr.gso_type == gso => {
            (packet.first().ok_or(OffloadError::Truncated)? >> 4, UDP)
        }
        _ => return Err(OffloadError::UnsupportedGso),
    };
    if hdr.gso_size == 0 {
        return Err(OffloadError::ZeroGsoSize);
    }
    if usize::from(hdr.hdr_len) > packet.len() {
        return Err(OffloadError::Truncated);
    }
    let ip_len = ip_header_len(packet, version, proto)?;
    let hlen = ip_len + transport_header_len(&packet[ip_len..], proto)?;
    let payload = &packet[hlen..];
    let gso_size = usize::from(hdr.gso_size);
    if hlen + gso_size.min(payload.len()) > MAX_IP_LEN {
        return Err(OffloadError::TooLong);
    }
    let count = payload.len().div_ceil(gso_size).max(1);
    for i in first..count {
        if out.is_full() {
            return Ok(Some(i));
        }
        let chunk = &payload[i * gso_size..payload.len().min((i + 1) * gso_size)];
        let mut buf = pool.get((hlen + chunk.len() + TAILROOM).max(capacity));
        buf.extend_from_slice(&packet[..hlen]);
        buf.extend_from_slice(chunk);
        fix_segment(buf.as_packet_mut(), ip_len, proto, i, count, i * gso_size);
        if let Some(next) = push(out, pool, buf, i) {
            return Ok(Some(next));
        }
    }
    Ok(None)
}

/// Appends `buf` (segment `i`) to `out`; if `out` is full, returns `buf` to `pool` and
/// yields `Some(i)`.
fn push(out: &mut PacketBatch, pool: &mut PacketPool, buf: PacketBuf, i: usize) -> Option<usize> {
    out.push(buf).err().map(|buf| {
        pool.put(buf);
        i
    })
}

/// Rewrites the copied headers of segment `i` of `count`, whose payload starts `offset`
/// bytes into the super-packet's payload.
fn fix_segment(seg: &mut [u8], ip_len: usize, proto: u8, i: usize, count: usize, offset: usize) {
    let len = seg.len();
    if ip_len == IPV6_HDR {
        put16(seg, 4, len - IPV6_HDR);
    } else {
        put16(seg, 2, len);
        let id = u16::from_be_bytes([seg[4], seg[5]]).wrapping_add(low16(i));
        seg[4..6].copy_from_slice(&id.to_be_bytes());
        seg[10..12].fill(0);
        let csum = !fold(sum(0, &seg[..ip_len]));
        seg[10..12].copy_from_slice(&csum.to_be_bytes());
    }
    let field = if proto == TCP {
        let tcp = ip_len;
        let seq = u32::from_be_bytes([seg[tcp + 4], seg[tcp + 5], seg[tcp + 6], seg[tcp + 7]]);
        seg[tcp + 4..tcp + 8].copy_from_slice(&seq.wrapping_add(low32(offset)).to_be_bytes());
        if i + 1 != count {
            seg[tcp + 13] &= !(TCP_FIN | TCP_PSH);
        }
        if i != 0 {
            seg[tcp + 13] &= !TCP_CWR;
        }
        tcp + TCP_CSUM_OFFSET
    } else {
        put16(seg, ip_len + 4, len - ip_len);
        ip_len + UDP_CSUM_OFFSET
    };
    seg[field..field + 2].fill(0);
    let mut csum = !fold(sum(
        pseudo_sum(seg, ip_len, proto, len - ip_len),
        &seg[ip_len..],
    ));
    if csum == 0 && proto == UDP {
        csum = 0xFFFF;
    }
    seg[field..field + 2].copy_from_slice(&csum.to_be_bytes());
}

/// Validates the IP header of a super-packet against `version` and `proto` and returns
/// its length.
fn ip_header_len(packet: &[u8], version: u8, proto: u8) -> Result<usize, OffloadError> {
    let first = *packet.first().ok_or(OffloadError::Truncated)?;
    if first >> 4 != version {
        return Err(OffloadError::BadHeaders);
    }
    if version == 6 {
        if packet.len() < IPV6_HDR {
            return Err(OffloadError::Truncated);
        }
        if packet[6] != proto {
            return Err(OffloadError::BadHeaders);
        }
        return Ok(IPV6_HDR);
    }
    let ihl = usize::from(first & 0x0F) * 4;
    if packet.len() < IPV4_HDR.max(ihl) {
        return Err(OffloadError::Truncated);
    }
    let fragment = u16::from_be_bytes([packet[6], packet[7]]) & 0x3FFF;
    if ihl < IPV4_HDR || packet[9] != proto || fragment != 0 {
        return Err(OffloadError::BadHeaders);
    }
    Ok(ihl)
}

/// Validates the transport header at the start of `l4` and returns its length.
fn transport_header_len(l4: &[u8], proto: u8) -> Result<usize, OffloadError> {
    let len = if proto == TCP {
        let offset = l4.get(12).ok_or(OffloadError::Truncated)?;
        let len = usize::from(offset >> 4) * 4;
        if len < TCP_HDR {
            return Err(OffloadError::BadHeaders);
        }
        len
    } else {
        UDP_HDR
    };
    if l4.len() < len {
        return Err(OffloadError::Truncated);
    }
    Ok(len)
}

/// The transport protocol of an IP packet without IPv6 extension headers.
fn l4_protocol(packet: &[u8]) -> Option<u8> {
    match packet.first()? >> 4 {
        4 => packet.get(9).copied(),
        6 => packet.get(6).copied(),
        _ => None,
    }
}

/// Builds GRO super-packets for writes toward the kernel.
///
/// [`Coalescer::coalesce`] partitions an ordered list of IP packets into groups. A group
/// of one packet is written as is behind a `GSO_NONE` header. A group of several
/// packets of one flow is a super-packet: its first packet's headers are patched in
/// place (IP length and IPv4 header checksum, UDP length, TCP PSH from the last packet,
/// and the transport checksum field set to the partial pseudo-header sum the kernel
/// completes per segment), and every following packet contributes only its payload.
///
/// Write shape for `writev`, per group in [`Coalescer::groups`] order:
/// `[group.hdr().encode(), parts...]` where [`Coalescer::parts`] yields the first
/// packet (headers included) followed by the payload slices of the other packets.
/// Nothing is copied.
///
/// TCP packets join a run when they have the same 5-tuple, the next sequence number,
/// the same ACK number, window and options, flags ACK (PSH allowed on the last packet
/// of the run), a payload no larger than the first packet's (a shorter one ends the
/// run), the same TOS, TTL and DF (IPv4) or traffic class, flow label and hop limit
/// (IPv6), no IPv4 options or IPv6 extension headers, and a valid checksum. UDP packets
/// (only if enabled: the kernel's USO support is optional) follow the same size,
/// header-field and checksum rules and must not be fragments. The IPv4 identification
/// is not compared: segmentation numbers it from the first packet's. A run holds at most
/// [`MAX_BATCH`] packets and 65535 bytes. Groups appear in the order of their first
/// packet; packets of one flow never change their relative order.
#[derive(Debug, Default)]
pub(crate) struct Coalescer {
    udp: bool,
    groups: Vec<Group>,
    /// Index of the next packet of the same group, per packet.
    next: Vec<Option<usize>>,
    /// Runs that may still grow.
    open: Vec<Open>,
}

/// One write toward the kernel: a single packet or a super-packet.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Group {
    hdr: VirtioNetHdr,
    first: usize,
    last: usize,
    count: usize,
    /// Header bytes of the first packet that the following packets skip.
    hlen: usize,
    ip_len: usize,
    proto: u8,
    gso_size: usize,
    /// Sum of the payload lengths.
    payload: usize,
}

impl Group {
    /// The virtio header to write in front of the group.
    pub(crate) const fn hdr(&self) -> VirtioNetHdr {
        self.hdr
    }

    /// Number of packets in the group.
    pub(crate) const fn len(&self) -> usize {
        self.count
    }
}

/// A run that may still grow.
#[derive(Debug)]
struct Open {
    group: usize,
    key: FlowKey,
    /// TCP: the sequence number the next packet must carry.
    next_seq: u32,
}

/// The 5-tuple and IP version of a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FlowKey {
    proto: u8,
    v6: bool,
    addrs: [u8; 32],
    ports: [u8; 4],
}

/// How one packet takes part in coalescing.
enum Class {
    /// Not TCP or UDP (or UDP with UDP coalescing off): passes through.
    Other,
    /// Could belong to any flow (a non-first fragment or an IPv6 extension header):
    /// passes through and ends every open run.
    Unknown,
    /// TCP or UDP of a known flow.
    Flow(Candidate),
}

/// A TCP or UDP packet of a known flow.
struct Candidate {
    key: FlowKey,
    ip_len: usize,
    hlen: usize,
    payload: usize,
    /// Whether the packet may be part of a run at all.
    mergeable: bool,
    seq: u32,
    psh: bool,
}

impl Coalescer {
    /// Creates a coalescer; `udp` enables UDP runs (`GSO_UDP_L4`).
    pub(crate) const fn new(udp: bool) -> Self {
        Self {
            udp,
            groups: Vec::new(),
            next: Vec::new(),
            open: Vec::new(),
        }
    }

    /// Partitions `packets` into [`Coalescer::groups`], patching the first packet of
    /// every super-packet in place. Replaces the previous result.
    pub(crate) fn coalesce(&mut self, packets: &mut [PacketBuf]) {
        self.groups.clear();
        self.open.clear();
        self.next.clear();
        self.next.resize(packets.len(), None);
        for (i, packet) in packets.iter().enumerate() {
            match classify(packet.as_packet(), self.udp) {
                Class::Other => self.single(i, 0, 0, 0, 0),
                Class::Unknown => {
                    self.open.clear();
                    self.single(i, 0, 0, 0, 0);
                }
                Class::Flow(c) => {
                    if let Some(pos) = self.open.iter().position(|o| o.key == c.key) {
                        if c.mergeable && self.try_append(pos, i, &c, packets) {
                            continue;
                        }
                        self.open.swap_remove(pos);
                    }
                    self.single(i, c.ip_len, c.hlen, c.key.proto, c.payload);
                    if c.mergeable && !c.psh {
                        self.open.push(Open {
                            group: self.groups.len() - 1,
                            key: c.key,
                            next_seq: c.seq.wrapping_add(low32(c.payload)),
                        });
                    }
                }
            }
        }
        for g in 0..self.groups.len() {
            if self.groups[g].count > 1 {
                self.finish(g, packets);
            }
        }
    }

    /// The groups of the last [`Coalescer::coalesce`], in write order.
    pub(crate) fn groups(&self) -> &[Group] {
        &self.groups
    }

    /// Indices of the packets of `group`, in order.
    pub(crate) fn members(&self, group: &Group) -> impl Iterator<Item = usize> + '_ {
        iter::successors(Some(group.first), |&i| self.next.get(i).copied().flatten())
    }

    /// The bytes to write after `group`'s virtio header: the first packet whole, then
    /// the payload of every following packet. `packets` is the slice given to
    /// [`Coalescer::coalesce`].
    pub(crate) fn parts<'a>(
        &'a self,
        group: &Group,
        packets: &'a [PacketBuf],
    ) -> impl Iterator<Item = &'a [u8]> + 'a {
        let (first, hlen) = (group.first, group.hlen);
        self.members(group).filter_map(move |i| {
            let packet = packets.get(i)?.as_packet();
            if i == first {
                Some(packet)
            } else {
                packet.get(hlen..)
            }
        })
    }

    /// Starts a group holding packet `i` alone.
    fn single(&mut self, i: usize, ip_len: usize, hlen: usize, proto: u8, payload: usize) {
        self.groups.push(Group {
            hdr: VirtioNetHdr::default(),
            first: i,
            last: i,
            count: 1,
            hlen,
            ip_len,
            proto,
            gso_size: payload,
            payload,
        });
    }

    /// Appends packet `i` to the open run `pos` if it fits; closes the run if `i` ends it.
    fn try_append(&mut self, pos: usize, i: usize, c: &Candidate, packets: &[PacketBuf]) -> bool {
        let open = &self.open[pos];
        let group = &self.groups[open.group];
        let first = packets[group.first].as_packet();
        let packet = packets[i].as_packet();
        let room = MAX_IP_LEN.saturating_sub(group.hlen + group.payload);
        let fits = c.hlen == group.hlen
            && c.payload <= group.gso_size.min(room)
            && group.count < MAX_SEGMENTS
            && same_ip_fields(first, packet)
            && (c.key.proto != TCP
                || (c.seq == open.next_seq && same_tcp_fields(first, packet, c.ip_len, c.hlen)));
        if !fits {
            return false;
        }
        let ends = c.psh || c.payload < group.gso_size;
        let next_seq = c.seq.wrapping_add(low32(c.payload));
        let g = open.group;
        let group = &mut self.groups[g];
        self.next[group.last] = Some(i);
        group.last = i;
        group.count += 1;
        group.payload += c.payload;
        if ends {
            self.open.swap_remove(pos);
        } else {
            self.open[pos].next_seq = next_seq;
        }
        true
    }

    /// Turns group `g` (several packets) into a super-packet: patches its first packet
    /// and sets its virtio header.
    fn finish(&mut self, g: usize, packets: &mut [PacketBuf]) {
        let group = &mut self.groups[g];
        let (ip_len, hlen) = (group.ip_len, group.hlen);
        let len = hlen + group.payload;
        let psh = group.proto == TCP && packets[group.last].as_packet()[ip_len + 13] & TCP_PSH != 0;
        let p = packets[group.first].as_packet_mut();
        let v6 = ip_len == IPV6_HDR;
        if v6 {
            put16(p, 4, len - IPV6_HDR);
        } else {
            put16(p, 2, len);
            p[10..12].fill(0);
            let csum = !fold(sum(0, &p[..ip_len]));
            p[10..12].copy_from_slice(&csum.to_be_bytes());
        }
        let (gso_type, csum_offset) = if group.proto == TCP {
            if psh {
                p[ip_len + 13] |= TCP_PSH;
            }
            let gso = if v6 {
                VirtioNetHdr::GSO_TCPV6
            } else {
                VirtioNetHdr::GSO_TCPV4
            };
            (gso, TCP_CSUM_OFFSET)
        } else {
            put16(p, ip_len + 4, len - ip_len);
            (VirtioNetHdr::GSO_UDP_L4, UDP_CSUM_OFFSET)
        };
        let partial = fold(pseudo_sum(p, ip_len, group.proto, len - ip_len));
        p[ip_len + csum_offset..ip_len + csum_offset + 2].copy_from_slice(&partial.to_be_bytes());
        group.hdr = VirtioNetHdr {
            flags: VirtioNetHdr::F_NEEDS_CSUM,
            gso_type,
            hdr_len: low16(hlen),
            gso_size: low16(group.gso_size),
            csum_start: low16(ip_len),
            csum_offset: low16(csum_offset),
        };
    }
}

/// Classifies one packet for coalescing.
fn classify(packet: &[u8], udp: bool) -> Class {
    let Some(&first) = packet.first() else {
        return Class::Other;
    };
    let (v6, ip_len, proto, mut mergeable) = match first >> 4 {
        4 if packet.len() >= IPV4_HDR => {
            let ihl = usize::from(first & 0x0F) * 4;
            let frag = u16::from_be_bytes([packet[6], packet[7]]);
            let proto = packet[9];
            if ihl < IPV4_HDR || ihl > packet.len() || !(proto == TCP || (udp && proto == UDP)) {
                return Class::Other;
            }
            if frag & 0x1FFF != 0 {
                return Class::Unknown;
            }
            let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            let plain = ihl == IPV4_HDR && frag & 0x2000 == 0 && total == packet.len();
            (false, ihl, proto, plain)
        }
        6 if packet.len() >= IPV6_HDR => {
            let proto = packet[6];
            if !(proto == TCP || proto == UDP) {
                // ICMPv6 and "no next header" carry no transport flow.
                return if proto == 58 || proto == 59 {
                    Class::Other
                } else {
                    Class::Unknown
                };
            }
            if proto == UDP && !udp {
                return Class::Other;
            }
            let payload = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            (true, IPV6_HDR, proto, payload + IPV6_HDR == packet.len())
        }
        _ => return Class::Other,
    };
    let l4 = &packet[ip_len..];
    let Ok(l4_len) = transport_header_len(l4, proto) else {
        return Class::Other;
    };
    let mut key = FlowKey {
        proto,
        v6,
        addrs: [0; 32],
        ports: [l4[0], l4[1], l4[2], l4[3]],
    };
    if v6 {
        key.addrs.copy_from_slice(&packet[8..40]);
    } else {
        key.addrs[..8].copy_from_slice(&packet[12..20]);
    }
    let hlen = ip_len + l4_len;
    let payload = packet.len() - hlen;
    let (seq, psh) = if proto == TCP {
        let flags = l4[13];
        mergeable &= flags & !TCP_PSH == TCP_ACK;
        (
            u32::from_be_bytes([l4[4], l4[5], l4[6], l4[7]]),
            flags & TCP_PSH != 0,
        )
    } else {
        mergeable &= usize::from(u16::from_be_bytes([l4[4], l4[5]])) == l4.len();
        (0, false)
    };
    mergeable = mergeable && payload > 0 && checksum_valid(packet, ip_len, proto);
    Class::Flow(Candidate {
        key,
        ip_len,
        hlen,
        payload,
        mergeable,
        seq,
        psh,
    })
}

/// Whether the IP header fields copied into every segment are equal: TOS, DF and TTL
/// (IPv4) or traffic class, flow label and hop limit (IPv6). Version, protocol and
/// addresses are part of the flow key.
fn same_ip_fields(a: &[u8], b: &[u8]) -> bool {
    if a[0] >> 4 == 6 {
        a[..4] == b[..4] && a[7] == b[7]
    } else {
        a[1] == b[1] && a[6] & 0x40 == b[6] & 0x40 && a[8] == b[8]
    }
}

/// Whether the TCP ACK number, window and options of `a` and `b` are equal.
fn same_tcp_fields(a: &[u8], b: &[u8], ip_len: usize, hlen: usize) -> bool {
    let tcp = ip_len;
    a[tcp + 8..tcp + 12] == b[tcp + 8..tcp + 12]
        && a[tcp + 14..tcp + 16] == b[tcp + 14..tcp + 16]
        && a[tcp + TCP_HDR..hlen] == b[tcp + TCP_HDR..hlen]
}

/// Whether the transport checksum of `packet` is valid (an IPv4 UDP checksum of 0
/// means none).
fn checksum_valid(packet: &[u8], ip_len: usize, proto: u8) -> bool {
    let l4 = &packet[ip_len..];
    if proto == UDP && ip_len != IPV6_HDR && l4[6..8] == [0, 0] {
        return true;
    }
    fold(sum(pseudo_sum(packet, ip_len, proto, l4.len()), l4)) == 0xFFFF
}

/// Unfolded sum of the pseudo-header of `packet` for a transport length `l4_len`.
fn pseudo_sum(packet: &[u8], ip_len: usize, proto: u8, l4_len: usize) -> u64 {
    let addrs = if ip_len == IPV6_HDR {
        &packet[8..40]
    } else {
        &packet[12..20]
    };
    sum(u64::from(proto) + l4_len as u64, addrs)
}

/// Adds `data` to `acc` as big-endian 16-bit words (an odd trailing byte is padded with
/// zero), eight bytes at a time.
fn sum(mut acc: u64, data: &[u8]) -> u64 {
    let (words, rest) = data.as_chunks::<8>();
    for w in words {
        let w = u64::from_be_bytes(*w);
        acc += (w >> 32) + (w & 0xFFFF_FFFF);
    }
    let (pairs, tail) = rest.as_chunks::<2>();
    for p in pairs {
        acc += u64::from(u16::from_be_bytes(*p));
    }
    if let [last] = tail {
        acc += u64::from(*last) << 8;
    }
    acc
}

/// Folds the carries of `acc` into 16 bits (not complemented).
const fn fold(mut acc: u64) -> u16 {
    while acc > 0xFFFF {
        acc = (acc & 0xFFFF) + (acc >> 16);
    }
    let [.., hi, lo] = acc.to_be_bytes();
    u16::from_be_bytes([hi, lo])
}

/// Writes the low 16 bits of `value` big-endian at `at`.
fn put16(packet: &mut [u8], at: usize, value: usize) {
    packet[at..at + 2].copy_from_slice(&low16(value).to_be_bytes());
}

/// The low 16 bits of `value`.
const fn low16(value: usize) -> u16 {
    let [lo, hi, ..] = value.to_le_bytes();
    u16::from_le_bytes([lo, hi])
}

/// The low 32 bits of `value`.
const fn low32(value: usize) -> u32 {
    let [a, b, c, d, ..] = value.to_le_bytes();
    u32::from_le_bytes([a, b, c, d])
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use nsplane_packet::checksum::{
        internet_checksum, transport_checksum_v4, transport_checksum_v6,
    };

    use super::*;

    const SRC4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const DST4: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
    const SRC6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
    const DST6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);

    /// Header fields of a test packet.
    #[derive(Clone)]
    struct Spec {
        v6: bool,
        proto: u8,
        sport: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        window: u16,
        tos: u8,
        ttl: u8,
        id: u16,
        df: bool,
        flow: u32,
        tcp_options: Vec<u8>,
        ip_options: Vec<u8>,
    }

    fn spec(v6: bool, proto: u8) -> Spec {
        Spec {
            v6,
            proto,
            sport: 40000,
            seq: 0xFFFF_FF00,
            ack: 77,
            flags: TCP_ACK,
            window: 512,
            tos: 0,
            ttl: 64,
            id: 0xFFF0,
            df: true,
            flow: 0x12345,
            tcp_options: Vec::new(),
            ip_options: Vec::new(),
        }
    }

    impl Spec {
        fn ip_len(&self) -> usize {
            if self.v6 {
                IPV6_HDR
            } else {
                IPV4_HDR + self.ip_options.len()
            }
        }

        fn hlen(&self) -> usize {
            self.ip_len()
                + if self.proto == TCP {
                    TCP_HDR + self.tcp_options.len()
                } else {
                    UDP_HDR
                }
        }

        /// The spec of the `i`-th packet of a flow whose earlier packets carried
        /// `offset` payload bytes.
        fn nth(&self, i: usize, offset: usize) -> Self {
            let mut s = self.clone();
            s.seq = s.seq.wrapping_add(u32::try_from(offset).unwrap());
            s.id = s.id.wrapping_add(u16::try_from(i).unwrap());
            s
        }
    }

    /// `len` payload bytes as found at `offset` of a flow's byte stream.
    fn payload(offset: usize, len: usize) -> Vec<u8> {
        (offset..offset + len)
            .map(|k| u8::try_from(k % 251).unwrap())
            .collect()
    }

    /// Transport checksum computed with nsplane-packet's helpers.
    fn l4_checksum(v6: bool, proto: u8, l4: &[u8]) -> u16 {
        if v6 {
            transport_checksum_v6(SRC6, DST6, proto, l4)
        } else {
            transport_checksum_v4(SRC4, DST4, proto, l4)
        }
    }

    /// A valid packet built with nsplane-packet's checksum helpers.
    fn build(s: &Spec, data: &[u8]) -> Vec<u8> {
        let ip_len = s.ip_len();
        let hlen = s.hlen();
        let len = hlen + data.len();
        let mut p = vec![0; len];
        if s.v6 {
            let word = (6 << 28) | (u32::from(s.tos) << 20) | s.flow;
            p[..4].copy_from_slice(&word.to_be_bytes());
            put16(&mut p, 4, len - IPV6_HDR);
            p[6] = s.proto;
            p[7] = s.ttl;
            p[8..24].copy_from_slice(&SRC6.octets());
            p[24..40].copy_from_slice(&DST6.octets());
        } else {
            p[0] = 0x40 | u8::try_from(ip_len / 4).unwrap();
            p[1] = s.tos;
            put16(&mut p, 2, len);
            p[4..6].copy_from_slice(&s.id.to_be_bytes());
            p[6] = if s.df { 0x40 } else { 0 };
            p[8] = s.ttl;
            p[9] = s.proto;
            p[12..16].copy_from_slice(&SRC4.octets());
            p[16..20].copy_from_slice(&DST4.octets());
            p[IPV4_HDR..ip_len].copy_from_slice(&s.ip_options);
            let csum = internet_checksum(&p[..ip_len]);
            p[10..12].copy_from_slice(&csum.to_be_bytes());
        }
        let l4 = ip_len;
        p[l4..l4 + 2].copy_from_slice(&s.sport.to_be_bytes());
        p[l4 + 2..l4 + 4].copy_from_slice(&443u16.to_be_bytes());
        let field = if s.proto == TCP {
            p[l4 + 4..l4 + 8].copy_from_slice(&s.seq.to_be_bytes());
            p[l4 + 8..l4 + 12].copy_from_slice(&s.ack.to_be_bytes());
            p[l4 + 12] = u8::try_from((hlen - ip_len) / 4).unwrap() << 4;
            p[l4 + 13] = s.flags;
            p[l4 + 14..l4 + 16].copy_from_slice(&s.window.to_be_bytes());
            p[l4 + TCP_HDR..hlen].copy_from_slice(&s.tcp_options);
            l4 + TCP_CSUM_OFFSET
        } else {
            put16(&mut p, l4 + 4, len - ip_len);
            l4 + UDP_CSUM_OFFSET
        };
        p[hlen..].copy_from_slice(data);
        let mut csum = l4_checksum(s.v6, s.proto, &p[ip_len..]);
        if csum == 0 && s.proto == UDP {
            csum = 0xFFFF;
        }
        p[field..field + 2].copy_from_slice(&csum.to_be_bytes());
        p
    }

    /// The partial (pseudo-header only) checksum the kernel leaves in `packet` for
    /// `l4_len` transport bytes.
    fn partial(packet: &[u8], proto: u8, l4_len: usize) -> u16 {
        let zeros = vec![0; l4_len];
        if packet[0] >> 4 == 6 {
            let src: [u8; 16] = packet[8..24].try_into().unwrap();
            let dst: [u8; 16] = packet[24..40].try_into().unwrap();
            !transport_checksum_v6(src.into(), dst.into(), proto, &zeros)
        } else {
            let src: [u8; 4] = packet[12..16].try_into().unwrap();
            let dst: [u8; 4] = packet[16..20].try_into().unwrap();
            !transport_checksum_v4(src.into(), dst.into(), proto, &zeros)
        }
    }

    /// Asserts lengths and checksums of `p` with nsplane-packet's helpers.
    fn assert_valid(p: &[u8]) {
        let v6 = p[0] >> 4 == 6;
        let (ip_len, proto) = if v6 {
            assert_eq!(
                usize::from(u16::from_be_bytes([p[4], p[5]])) + IPV6_HDR,
                p.len()
            );
            (IPV6_HDR, p[6])
        } else {
            let ihl = usize::from(p[0] & 0x0F) * 4;
            assert_eq!(usize::from(u16::from_be_bytes([p[2], p[3]])), p.len());
            assert_eq!(internet_checksum(&p[..ihl]), 0, "IPv4 header checksum");
            (ihl, p[9])
        };
        if proto == UDP {
            let udp_len = u16::from_be_bytes([p[ip_len + 4], p[ip_len + 5]]);
            assert_eq!(usize::from(udp_len), p.len() - ip_len);
        }
        assert_eq!(
            l4_checksum(v6, proto, &p[ip_len..]),
            0,
            "transport checksum"
        );
    }

    /// A super-packet of `len` payload bytes as the kernel hands it over, with the
    /// partial checksum and a vnet header for `gso_size`.
    fn super_packet(s: &Spec, len: usize, gso_size: usize) -> (VirtioNetHdr, Vec<u8>) {
        let mut p = build(s, &payload(0, len));
        let (ip_len, hlen) = (s.ip_len(), s.hlen());
        let offset = if s.proto == TCP {
            TCP_CSUM_OFFSET
        } else {
            UDP_CSUM_OFFSET
        };
        let csum = partial(&p, s.proto, p.len() - ip_len);
        p[ip_len + offset..ip_len + offset + 2].copy_from_slice(&csum.to_be_bytes());
        let gso_type = match (s.proto, s.v6) {
            (TCP, false) => VirtioNetHdr::GSO_TCPV4 | VirtioNetHdr::GSO_ECN,
            (TCP, true) => VirtioNetHdr::GSO_TCPV6 | VirtioNetHdr::GSO_ECN,
            _ => VirtioNetHdr::GSO_UDP_L4,
        };
        let hdr = VirtioNetHdr {
            flags: VirtioNetHdr::F_NEEDS_CSUM,
            gso_type,
            hdr_len: u16::try_from(hlen).unwrap(),
            gso_size: u16::try_from(gso_size).unwrap(),
            csum_start: u16::try_from(ip_len).unwrap(),
            csum_offset: u16::try_from(offset).unwrap(),
        };
        (hdr, p)
    }

    /// Segments `packet` completely, one batch after another.
    fn run(hdr: &VirtioNetHdr, packet: &[u8]) -> Result<Vec<Vec<u8>>, OffloadError> {
        let mut pool = PacketPool::new(MAX_BATCH);
        let mut segments = Vec::new();
        let mut first = 0;
        loop {
            let mut out = PacketBatch::new();
            let next = segment(hdr, packet, first, 0, &mut pool, &mut out)?;
            segments.extend(out.iter().map(|p| p.as_packet().to_vec()));
            match next {
                Some(next) => first = next,
                None => return Ok(segments),
            }
        }
    }

    #[test]
    fn header_round_trip() {
        let hdr = VirtioNetHdr {
            flags: VirtioNetHdr::F_NEEDS_CSUM,
            gso_type: VirtioNetHdr::GSO_TCPV6 | VirtioNetHdr::GSO_ECN,
            hdr_len: 0x0102,
            gso_size: 1380,
            csum_start: 40,
            csum_offset: 16,
        };
        let bytes = hdr.encode();
        assert_eq!(bytes.len(), VirtioNetHdr::LEN);
        assert_eq!(bytes[..2], [1, 0x84]);
        assert_eq!(bytes[2..4], 0x0102u16.to_ne_bytes());
        assert_eq!(bytes[4..6], 1380u16.to_ne_bytes());
        assert_eq!(VirtioNetHdr::parse(&bytes), Ok(hdr));
        let mut longer = bytes.to_vec();
        longer.extend_from_slice(&[0x45, 0]);
        assert_eq!(VirtioNetHdr::parse(&longer), Ok(hdr));
        assert_eq!(
            VirtioNetHdr::parse(&bytes[..9]),
            Err(OffloadError::Truncated)
        );
        assert_eq!(VirtioNetHdr::parse(&[]), Err(OffloadError::Truncated));
        assert_eq!(VirtioNetHdr::parse(&[0; 10]), Ok(VirtioNetHdr::default()));
    }

    /// Segments super-packets of every interesting size for `v6`/`proto` and compares
    /// each segment with the packet a sender would have built.
    fn check_segmentation(v6: bool, proto: u8) {
        let mut s = spec(v6, proto);
        if proto == TCP {
            s.flags = TCP_ACK | TCP_PSH | TCP_FIN | TCP_CWR;
        }
        let overhead = s.hlen();
        for mtu in [1280, 1420, 1500] {
            let g = mtu - overhead;
            for len in [1, g - 1, g, g + 1, 3 * g, 3 * g + 1, MAX_IP_LEN - overhead] {
                let (hdr, packet) = super_packet(&s, len, g);
                let segments = run(&hdr, &packet).unwrap();
                assert_eq!(segments.len(), len.div_ceil(g), "mtu {mtu} len {len}");
                for (i, seg) in segments.iter().enumerate() {
                    assert_valid(seg);
                    let mut si = s.nth(i, i * g);
                    if i + 1 != segments.len() {
                        si.flags &= !(TCP_FIN | TCP_PSH);
                    }
                    if i != 0 {
                        si.flags &= !TCP_CWR;
                    }
                    let data = payload(i * g, g.min(len - i * g));
                    assert_eq!(*seg, build(&si, &data), "mtu {mtu} len {len} segment {i}");
                }
            }
        }
    }

    #[test]
    fn segments_tcpv4() {
        check_segmentation(false, TCP);
    }

    #[test]
    fn segments_tcpv6() {
        check_segmentation(true, TCP);
    }

    #[test]
    fn segments_udpv4() {
        check_segmentation(false, UDP);
    }

    #[test]
    fn segments_udpv6() {
        check_segmentation(true, UDP);
    }

    #[test]
    fn segments_tcp_with_options() {
        let mut s = spec(false, TCP);
        s.tcp_options = vec![1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2];
        let (hdr, packet) = super_packet(&s, 2500, 1000);
        let segments = run(&hdr, &packet).unwrap();
        assert_eq!(segments.len(), 3);
        for (i, seg) in segments.iter().enumerate() {
            assert_valid(seg);
            let data = payload(i * 1000, 1000.min(2500 - i * 1000));
            assert_eq!(*seg, build(&s.nth(i, i * 1000), &data));
        }
    }

    #[test]
    fn segmentation_continues_across_batches() {
        let s = spec(false, TCP);
        let (hdr, packet) = super_packet(&s, 100 * 70 + 5, 100);
        let mut pool = PacketPool::new(0);
        let mut out = PacketBatch::new();
        assert_eq!(
            segment(&hdr, &packet, 0, 0, &mut pool, &mut out),
            Ok(Some(MAX_BATCH))
        );
        assert!(out.is_full());
        let mut segments: Vec<Vec<u8>> = out.drain().map(|p| p.as_packet().to_vec()).collect();
        assert_eq!(
            segment(&hdr, &packet, MAX_BATCH, 0, &mut pool, &mut out),
            Ok(None)
        );
        assert_eq!(out.len(), 71 - MAX_BATCH);
        segments.extend(out.drain().map(|p| p.as_packet().to_vec()));
        assert_eq!(segments, run(&hdr, &packet).unwrap());
        for (i, seg) in segments.iter().enumerate() {
            assert_eq!(
                *seg,
                build(
                    &s.nth(i, i * 100),
                    &payload(i * 100, 100.min(7005 - i * 100))
                )
            );
        }

        // A partly filled batch takes what fits; a full one takes nothing.
        let mut out = PacketBatch::new();
        for _ in 0..MAX_BATCH - 4 {
            out.push(PacketBuf::with_capacity(0)).unwrap();
        }
        assert_eq!(
            segment(&hdr, &packet, 0, 0, &mut pool, &mut out),
            Ok(Some(4))
        );
        assert_eq!(
            segment(&hdr, &packet, 4, 0, &mut pool, &mut out),
            Ok(Some(4))
        );
        let none = VirtioNetHdr::default();
        assert_eq!(
            segment(&none, &packet, 0, 0, &mut pool, &mut out),
            Ok(Some(0))
        );
        assert_eq!(segment(&none, &packet, 1, 0, &mut pool, &mut out), Ok(None));
    }

    #[test]
    fn completes_needs_csum() {
        for (v6, proto) in [(false, TCP), (true, TCP), (false, UDP), (true, UDP)] {
            let s = spec(v6, proto);
            let expected = build(&s, &payload(0, 333));
            let (mut hdr, packet) = super_packet(&s, 333, 1000);
            assert_ne!(packet, expected);
            hdr.gso_type = VirtioNetHdr::GSO_NONE;
            hdr.gso_size = 0;
            hdr.hdr_len = 0;
            let segments = run(&hdr, &packet).unwrap();
            assert_eq!(segments, [expected]);
            assert_valid(&segments[0]);
        }
    }

    #[test]
    fn gso_none_passes_packet_through() {
        let hdr = VirtioNetHdr::default();
        let bytes = [0xAB; 77];
        assert_eq!(run(&hdr, &bytes).unwrap(), [bytes.to_vec()]);
        assert_eq!(run(&hdr, &[]).unwrap(), [Vec::<u8>::new()]);
        let mut pool = PacketPool::new(1);
        let mut out = PacketBatch::new();
        segment(&hdr, &bytes, 0, 0, &mut pool, &mut out).unwrap();
        let buf = out.iter_mut().next().unwrap();
        assert_eq!(buf.with_headroom_mut().len(), nsplane::HEADROOM + 77);
    }

    #[test]
    fn packets_get_at_least_the_requested_capacity() {
        let s = spec(false, TCP);
        let (hdr, packet) = super_packet(&s, 3000, 1000);
        let none = VirtioNetHdr::default();
        let mut pool = PacketPool::new(0);
        for capacity in [0, 1528, 1040] {
            let mut out = PacketBatch::new();
            assert_eq!(
                segment(&hdr, &packet, 0, capacity, &mut pool, &mut out),
                Ok(None)
            );
            assert_eq!(out.len(), 3);
            assert_eq!(
                segment(&none, &packet[..77], 0, capacity, &mut pool, &mut out),
                Ok(None)
            );
            for p in out.iter() {
                assert!(p.capacity() >= capacity.max(p.len() + TAILROOM));
                assert_eq!(p.headroom(), nsplane::HEADROOM);
            }
        }
    }

    #[test]
    fn segments_reuse_pooled_buffers_without_growth() {
        let s = spec(false, TCP);
        let (hdr, packet) = super_packet(&s, 3000, 1000);
        let mut pool = PacketPool::new(8);
        // Buffers that held larger packets before: reused, overwritten, not grown.
        for _ in 0..3 {
            let mut old = pool.get(1600);
            old.extend_from_slice(&[0xEE; 1600]);
            pool.put(old);
        }
        let mut fresh = PacketBatch::new();
        segment(&hdr, &packet, 0, 0, &mut PacketPool::new(0), &mut fresh).unwrap();
        let mut out = PacketBatch::new();
        segment(&hdr, &packet, 0, 1500 + TAILROOM, &mut pool, &mut out).unwrap();
        assert_eq!(pool.free_len(), 0);
        let got: Vec<&[u8]> = out.iter().map(PacketBuf::as_packet).collect();
        let want: Vec<&[u8]> = fresh.iter().map(PacketBuf::as_packet).collect();
        assert_eq!(got, want);
        for p in out.iter() {
            assert!(p.capacity() >= 1500 + TAILROOM);
        }
    }

    #[test]
    fn rejects_malformed_input() {
        let s = spec(false, TCP);
        let (hdr, packet) = super_packet(&s, 3000, 1000);
        let err = |hdr: &VirtioNetHdr, packet: &[u8]| run(hdr, packet).unwrap_err();

        assert_eq!(
            err(&VirtioNetHdr { gso_size: 0, ..hdr }, &packet),
            OffloadError::ZeroGsoSize
        );
        for gso_type in [
            2,
            3,
            6,
            0x7F,
            VirtioNetHdr::GSO_UDP_L4 | VirtioNetHdr::GSO_ECN,
            0x80,
        ] {
            assert_eq!(
                err(&VirtioNetHdr { gso_type, ..hdr }, &packet),
                OffloadError::UnsupportedGso
            );
        }
        let hdr_len = u16::try_from(packet.len() + 1).unwrap();
        assert_eq!(
            err(&VirtioNetHdr { hdr_len, ..hdr }, &packet),
            OffloadError::Truncated
        );
        let v6 = VirtioNetHdr {
            gso_type: VirtioNetHdr::GSO_TCPV6,
            ..hdr
        };
        assert_eq!(err(&v6, &packet), OffloadError::BadHeaders);
        let udp = VirtioNetHdr {
            gso_type: VirtioNetHdr::GSO_UDP_L4,
            ..hdr
        };
        assert_eq!(err(&udp, &packet), OffloadError::BadHeaders);
        assert_eq!(err(&hdr, &[]), OffloadError::Truncated);
        assert_eq!(err(&udp, &[]), OffloadError::Truncated);

        let mut bad = packet.clone();
        bad[0] = 0x44;
        assert_eq!(err(&hdr, &bad), OffloadError::BadHeaders);
        let mut bad = packet.clone();
        bad[0] = 0x4F;
        assert_eq!(
            err(&VirtioNetHdr { hdr_len: 0, ..hdr }, &bad[..50]),
            OffloadError::Truncated
        );
        let mut bad = packet.clone();
        bad[6] |= 0x20;
        assert_eq!(err(&hdr, &bad), OffloadError::BadHeaders);
        let mut bad = packet.clone();
        bad[32] = 0x40;
        assert_eq!(err(&hdr, &bad), OffloadError::BadHeaders);
        let mut bad = packet.clone();
        bad[32] = 0xF0;
        assert_eq!(
            err(&VirtioNetHdr { hdr_len: 0, ..hdr }, &bad[..70]),
            OffloadError::Truncated
        );
        let mut v6_ext = build(&spec(true, TCP), &[1; 10]);
        v6_ext[6] = 0;
        assert_eq!(err(&v6, &v6_ext), OffloadError::BadHeaders);

        let too_long = VirtioNetHdr {
            gso_size: u16::MAX,
            ..hdr
        };
        let mut big = packet.clone();
        big.resize(70_000, 0);
        assert_eq!(err(&too_long, &big), OffloadError::TooLong);

        let csum = VirtioNetHdr {
            csum_start: 3030,
            csum_offset: 16,
            ..VirtioNetHdr::default()
        };
        let csum = VirtioNetHdr {
            flags: VirtioNetHdr::F_NEEDS_CSUM,
            ..csum
        };
        assert_eq!(err(&csum, &packet), OffloadError::BadChecksumOffset);
        let max = VirtioNetHdr {
            csum_start: u16::MAX,
            csum_offset: u16::MAX,
            ..csum
        };
        assert_eq!(err(&max, &packet), OffloadError::BadChecksumOffset);
        let ecn_none = VirtioNetHdr {
            gso_type: VirtioNetHdr::GSO_ECN,
            ..csum
        };
        assert_eq!(err(&ecn_none, &packet), OffloadError::UnsupportedGso);
    }

    #[test]
    fn truncated_and_random_input_never_panics() {
        let s = spec(false, TCP);
        let (hdr, packet) = super_packet(&s, 3000, 1000);
        for cut in 0..packet.len() {
            let hdr = VirtioNetHdr { hdr_len: 0, ..hdr };
            let result = run(&hdr, &packet[..cut]);
            if cut < s.hlen() {
                assert_eq!(result, Err(OffloadError::Truncated), "cut {cut}");
            }
        }
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..2000 {
            let mut raw = next().to_le_bytes();
            raw[0] &= 1;
            raw[1] %= 6;
            raw[5] &= 3;
            raw[7] &= 63;
            let hdr = VirtioNetHdr::parse(&[raw.as_slice(), &[0, 0]].concat()).unwrap();
            let cut = usize::from(u16::from_le_bytes([raw[2], raw[3]])) % (packet.len() + 1);
            let mut packet = packet[..cut].to_vec();
            for _ in 0..4 {
                let r = next();
                if let Some(byte) = packet.get_mut(usize::try_from(r % 64).unwrap()) {
                    *byte = r.to_le_bytes()[7];
                }
            }
            let _ = run(&hdr, &packet);
            let mut bufs: Vec<PacketBuf> = [&packet[..], &packet[..packet.len() / 2]]
                .into_iter()
                .map(PacketBuf::from_packet)
                .collect();
            Coalescer::new(true).coalesce(&mut bufs);
        }
    }

    /// The packets of one flow with consecutive sequence numbers and IDs.
    fn flow(s: &Spec, sizes: &[usize]) -> Vec<Vec<u8>> {
        let mut offset = 0;
        sizes
            .iter()
            .enumerate()
            .map(|(i, &len)| {
                let p = build(&s.nth(i, offset), &payload(offset, len));
                offset += len;
                p
            })
            .collect()
    }

    /// Coalesces `packets` and checks that every group segments back into its packets
    /// byte for byte; returns the coalescer, the patched buffers and the group layout.
    fn coalesce(udp: bool, packets: &[Vec<u8>]) -> (Coalescer, Vec<PacketBuf>, Vec<Vec<usize>>) {
        let mut bufs: Vec<PacketBuf> = packets.iter().map(|p| PacketBuf::from_packet(p)).collect();
        let mut c = Coalescer::new(udp);
        c.coalesce(&mut bufs);
        let layout: Vec<Vec<usize>> = c.groups().iter().map(|g| c.members(g).collect()).collect();
        let mut seen: Vec<usize> = layout.concat();
        seen.sort_unstable();
        assert_eq!(
            seen,
            (0..packets.len()).collect::<Vec<_>>(),
            "every packet once"
        );
        for (group, members) in c.groups().iter().zip(&layout) {
            assert_eq!(group.len(), members.len());
            let hdr = VirtioNetHdr::parse(&group.hdr().encode()).unwrap();
            let bytes = c.parts(group, &bufs).collect::<Vec<_>>().concat();
            let originals: Vec<Vec<u8>> = members.iter().map(|&i| packets[i].clone()).collect();
            if members.len() == 1 {
                assert_eq!(hdr, VirtioNetHdr::default());
                assert_eq!(bytes, originals[0]);
            } else {
                check_super_packet(&hdr, &bytes, &originals);
            }
            assert_eq!(run(&hdr, &bytes).unwrap(), originals);
        }
        (c, bufs, layout)
    }

    /// Checks the virtio header and patched headers of a super-packet.
    fn check_super_packet(hdr: &VirtioNetHdr, bytes: &[u8], originals: &[Vec<u8>]) {
        let v6 = bytes[0] >> 4 == 6;
        let (ip_len, proto) = if v6 {
            (IPV6_HDR, bytes[6])
        } else {
            (IPV4_HDR, bytes[9])
        };
        let (gso_type, l4_hdr, offset) = match (proto, v6) {
            (TCP, false) => (
                VirtioNetHdr::GSO_TCPV4,
                usize::from(bytes[ip_len + 12] >> 4) * 4,
                16,
            ),
            (TCP, true) => (
                VirtioNetHdr::GSO_TCPV6,
                usize::from(bytes[ip_len + 12] >> 4) * 4,
                16,
            ),
            _ => (VirtioNetHdr::GSO_UDP_L4, UDP_HDR, 6),
        };
        let hlen = ip_len + l4_hdr;
        assert_eq!(
            *hdr,
            VirtioNetHdr {
                flags: VirtioNetHdr::F_NEEDS_CSUM,
                gso_type,
                hdr_len: u16::try_from(hlen).unwrap(),
                gso_size: u16::try_from(originals[0].len() - hlen).unwrap(),
                csum_start: u16::try_from(ip_len).unwrap(),
                csum_offset: offset,
            }
        );
        let expected_len = hlen + originals.iter().map(|p| p.len() - hlen).sum::<usize>();
        assert_eq!(bytes.len(), expected_len);
        if v6 {
            assert_eq!(
                usize::from(u16::from_be_bytes([bytes[4], bytes[5]])),
                bytes.len() - 40
            );
        } else {
            assert_eq!(
                usize::from(u16::from_be_bytes([bytes[2], bytes[3]])),
                bytes.len()
            );
            assert_eq!(internet_checksum(&bytes[..ip_len]), 0);
        }
        let field = ip_len + usize::from(offset);
        let csum = u16::from_be_bytes([bytes[field], bytes[field + 1]]);
        assert_eq!(csum, partial(bytes, proto, bytes.len() - ip_len));
    }

    #[test]
    fn coalesces_interleaved_flows() {
        let flows = [
            spec(false, TCP),
            spec(true, TCP),
            spec(false, UDP),
            spec(true, UDP),
        ];
        let sizes = [1000, 1000, 1000, 400];
        let per_flow: Vec<Vec<Vec<u8>>> = flows.iter().map(|s| flow(s, &sizes)).collect();
        let mut icmp = build(&spec(false, TCP), &[0; 8]);
        icmp[9] = 1;
        let mut packets = Vec::new();
        let mut tags = Vec::new();
        for i in 0..sizes.len() {
            for (f, packets_of_flow) in per_flow.iter().enumerate() {
                packets.push(packets_of_flow[i].clone());
                tags.push(f);
            }
            if i == 1 {
                packets.push(icmp.clone());
                tags.push(usize::MAX);
            }
        }
        let by_tag = |tag: usize| -> Vec<usize> {
            tags.iter()
                .enumerate()
                .filter(|&(_, &t)| t == tag)
                .map(|(i, _)| i)
                .collect()
        };

        let (_, _, layout) = coalesce(true, &packets);
        assert_eq!(
            layout,
            [
                by_tag(0),
                by_tag(1),
                by_tag(2),
                by_tag(3),
                by_tag(usize::MAX)
            ]
        );

        let (c, _, layout) = coalesce(false, &packets);
        assert_eq!(layout[..2], [by_tag(0), by_tag(1)]);
        assert_eq!(layout.len(), 2 + 8 + 1);
        assert!(layout[2..].iter().all(|g| g.len() == 1));
        assert!(
            c.groups()[2..]
                .iter()
                .all(|g| g.hdr() == VirtioNetHdr::default())
        );
    }

    #[test]
    fn same_ports_different_addresses_do_not_mix() {
        let a = flow(&spec(false, TCP), &[100, 100]);
        let mut b = a.clone();
        for p in &mut b {
            p[19] = 3;
            p[10..12].fill(0);
            let csum = internet_checksum(&p[..20]);
            p[10..12].copy_from_slice(&csum.to_be_bytes());
            p[36..38].fill(0);
            let csum = transport_checksum_v4(SRC4, Ipv4Addr::new(10, 0, 0, 3), TCP, &p[20..]);
            p[36..38].copy_from_slice(&csum.to_be_bytes());
        }
        let packets = [a[0].clone(), b[0].clone(), a[1].clone(), b[1].clone()];
        let (_, _, layout) = coalesce(false, &packets);
        assert_eq!(layout, [vec![0, 2], vec![1, 3]]);
    }

    #[test]
    fn out_of_order_sequence_breaks_runs() {
        let mut packets = flow(&spec(false, TCP), &[500; 4]);
        packets.swap(1, 2);
        let (_, _, layout) = coalesce(false, &packets);
        assert_eq!(layout, [vec![0], vec![1], vec![2], vec![3]]);
    }

    /// Coalesces a 4-packet flow whose packet 2 is changed by `change`.
    fn layout_with_change(v6: bool, change: impl Fn(&mut Spec)) -> Vec<Vec<usize>> {
        let s = spec(v6, TCP);
        let mut packets = flow(&s, &[500; 4]);
        let mut changed = s.nth(2, 1000);
        change(&mut changed);
        packets[2] = build(&changed, &payload(1000, 500));
        coalesce(false, &packets).2
    }

    #[test]
    fn header_differences_break_runs() {
        let split = vec![vec![0, 1], vec![2], vec![3]];
        assert_eq!(layout_with_change(false, |s| s.ttl = 63), split);
        assert_eq!(layout_with_change(false, |s| s.tos = 4), split);
        assert_eq!(layout_with_change(false, |s| s.df = false), split);
        assert_eq!(layout_with_change(false, |s| s.ack += 1), split);
        assert_eq!(layout_with_change(false, |s| s.window += 1), split);
        assert_eq!(
            layout_with_change(false, |s| s.tcp_options = vec![1; 4]),
            split
        );
        assert_eq!(layout_with_change(false, |s| s.flags |= TCP_FIN), split);
        assert_eq!(layout_with_change(false, |s| s.flags |= 0x40), split);
        assert_eq!(
            layout_with_change(false, |s| s.flags = TCP_ACK | TCP_CWR),
            split
        );
        assert_eq!(
            layout_with_change(false, |s| s.ip_options = vec![1; 4]),
            split
        );
        assert_eq!(layout_with_change(true, |s| s.ttl = 1), split);
        assert_eq!(layout_with_change(true, |s| s.tos = 0x20), split);
        assert_eq!(layout_with_change(true, |s| s.flow = 7), split);
    }

    #[test]
    fn psh_ends_a_run() {
        assert_eq!(
            layout_with_change(false, |s| s.flags |= TCP_PSH),
            [vec![0, 1, 2], vec![3]]
        );
        let mut s = spec(false, TCP);
        s.flags |= TCP_PSH;
        let (_, _, layout) = coalesce(false, &flow(&s, &[300; 3]));
        assert_eq!(layout, [vec![0], vec![1], vec![2]]);
    }

    #[test]
    fn options_and_pure_acks() {
        let mut s = spec(false, TCP);
        s.tcp_options = vec![1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2];
        let (_, _, layout) = coalesce(false, &flow(&s, &[300; 3]));
        assert_eq!(layout, [vec![0, 1, 2]]);

        // A pure ACK of the flow passes through and ends the run.
        let mut packets = flow(&spec(true, TCP), &[300, 300, 0, 300]);
        packets.push(build(&spec(true, TCP).nth(4, 900), &payload(900, 300)));
        let (_, _, layout) = coalesce(false, &packets);
        assert_eq!(layout, [vec![0, 1], vec![2], vec![3, 4]]);

        let mut s = spec(false, TCP);
        s.ip_options = vec![1; 4];
        let (_, _, layout) = coalesce(false, &flow(&s, &[300; 2]));
        assert_eq!(layout, [vec![0], vec![1]]);
    }

    #[test]
    fn payload_sizes_bound_runs() {
        let s = spec(false, TCP);
        let (_, _, layout) = coalesce(false, &flow(&s, &[1000, 900, 1000]));
        assert_eq!(layout, [vec![0, 1], vec![2]]);
        let (_, _, layout) = coalesce(false, &flow(&s, &[100, 200, 200]));
        assert_eq!(layout, [vec![0], vec![1, 2]]);

        let (_, _, layout) = coalesce(false, &flow(&s, &[1400; 50]));
        assert_eq!(layout, [(0..46).collect::<Vec<_>>(), (46..50).collect()]);
        // A maximal IPv6 packet (65535-byte payload) leaves no room at all.
        let (_, _, layout) = coalesce(false, &flow(&spec(true, TCP), &[65515, 1]));
        assert_eq!(layout, [vec![0], vec![1]]);
        let (_, _, layout) = coalesce(false, &flow(&s, &[100; 70]));
        assert_eq!(
            layout,
            [
                (0..MAX_BATCH).collect::<Vec<_>>(),
                (MAX_BATCH..70).collect()
            ]
        );
    }

    #[test]
    fn udp_rules() {
        for v6 in [false, true] {
            let packets = flow(&spec(v6, UDP), &[1200, 1200, 1200, 1100, 1200]);
            let (_, _, layout) = coalesce(true, &packets);
            assert_eq!(layout, [vec![0, 1, 2, 3], vec![4]]);
            let (_, _, layout) = coalesce(false, &packets);
            assert_eq!(layout, [vec![0], vec![1], vec![2], vec![3], vec![4]]);
        }
        let mut packets = flow(&spec(false, UDP), &[600; 4]);
        packets[2][6] |= 0x20;
        packets[2][10..12].fill(0);
        let csum = internet_checksum(&packets[2][..20]);
        packets[2][10..12].copy_from_slice(&csum.to_be_bytes());
        let mut tail = packets[2].clone();
        tail[6..8].copy_from_slice(&0x0010u16.to_be_bytes());
        packets.insert(3, tail);
        let (_, _, layout) = coalesce(true, &packets);
        assert_eq!(layout, [vec![0, 1], vec![2], vec![3], vec![4]]);
    }

    #[test]
    fn unknown_and_corrupt_packets_end_runs() {
        let mut packets = flow(&spec(true, TCP), &[300; 4]);
        let mut ext = packets[0].clone();
        ext[6] = 0;
        packets.insert(2, ext);
        let (_, _, layout) = coalesce(false, &packets);
        assert_eq!(layout, [vec![0, 1], vec![2], vec![3, 4]]);

        let mut packets = flow(&spec(false, TCP), &[300; 4]);
        packets[1][100] ^= 0xFF;
        let (_, _, layout) = coalesce(false, &packets);
        assert_eq!(layout, [vec![0], vec![1], vec![2, 3]]);

        let packets = [vec![], vec![0x45; 10], vec![0x60; 39], vec![0x10; 60]];
        let (_, _, layout) = coalesce(true, &packets);
        assert_eq!(layout, [vec![0], vec![1], vec![2], vec![3]]);
    }

    #[test]
    fn round_trip_reproduces_packets() {
        for (v6, proto) in [(false, TCP), (true, TCP), (false, UDP), (true, UDP)] {
            let s = spec(v6, proto);
            for g in [1, 100, 1240, 1380] {
                for n in [2, 5, 47] {
                    let count = n.min((MAX_IP_LEN - s.hlen()) / g);
                    let mut sizes = vec![g; count];
                    *sizes.last_mut().unwrap() = g.div_ceil(2);
                    let (_, _, layout) = coalesce(true, &flow(&s, &sizes));
                    assert_eq!(layout, [(0..count).collect::<Vec<_>>()]);
                }
            }
        }
    }
}
