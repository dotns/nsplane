//! GRO coalescing for writes to a Linux TUN device in `IFF_VNET_HDR` mode; pure, no I/O.
//!
//! With `IFF_VNET_HDR` every packet crossing the TUN fd is preceded by a
//! [`VirtioNetHdr`]. A write may carry one super-packet that the kernel splits again (GRO
//! toward the kernel), which [`Coalescer`] builds from runs of packets of the same flow;
//! reads are split with [`nsplane_packet::vnet::segment`].

use std::iter;

use nsplane::{MAX_BATCH, PacketBuf};
use nsplane_packet::checksum::{fold, sum_words};
use nsplane_packet::vnet::VirtioNetHdr;

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
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;
/// Offset of the checksum field inside the TCP header.
const TCP_CSUM_OFFSET: usize = 16;
/// Offset of the checksum field inside the UDP header.
const UDP_CSUM_OFFSET: usize = 6;
/// Largest IP packet (and so largest super-packet) the coalescer produces.
const MAX_IP_LEN: usize = 65535;
/// Most packets one super-packet built by [`Coalescer`] carries, so that
/// [`segment`](nsplane_packet::vnet::segment) can always split it into a single batch.
const MAX_SEGMENTS: usize = MAX_BATCH;

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
    v6: bool,
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
                Class::Other => self.single(i, false, 0, 0, 0, 0),
                Class::Unknown => {
                    self.open.clear();
                    self.single(i, false, 0, 0, 0, 0);
                }
                Class::Flow(c) => {
                    if let Some(pos) = self.open.iter().position(|o| o.key == c.key) {
                        if c.mergeable && self.try_append(pos, i, &c, packets) {
                            continue;
                        }
                        self.open.swap_remove(pos);
                    }
                    self.single(i, c.key.v6, c.ip_len, c.hlen, c.key.proto, c.payload);
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
    fn single(
        &mut self,
        i: usize,
        v6: bool,
        ip_len: usize,
        hlen: usize,
        proto: u8,
        payload: usize,
    ) {
        self.groups.push(Group {
            hdr: VirtioNetHdr::default(),
            first: i,
            last: i,
            count: 1,
            hlen,
            ip_len,
            v6,
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
        let (v6, ip_len, hlen) = (group.v6, group.ip_len, group.hlen);
        let len = hlen + group.payload;
        let psh = group.proto == TCP && packets[group.last].as_packet()[ip_len + 13] & TCP_PSH != 0;
        let p = packets[group.first].as_packet_mut();
        if v6 {
            put16(p, 4, len - IPV6_HDR);
        } else {
            put16(p, 2, len);
            p[10..12].fill(0);
            let csum = !fold(sum_words(0, &p[..ip_len]));
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
        let partial = fold(pseudo_sum(p, v6, group.proto, len - ip_len));
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
    let Some(l4_len) = transport_header_len(l4, proto) else {
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
    mergeable = mergeable && payload > 0 && checksum_valid(packet, v6, ip_len, proto);
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
fn checksum_valid(packet: &[u8], v6: bool, ip_len: usize, proto: u8) -> bool {
    let l4 = &packet[ip_len..];
    if proto == UDP && !v6 && l4[6..8] == [0, 0] {
        return true;
    }
    fold(sum_words(pseudo_sum(packet, v6, proto, l4.len()), l4)) == 0xFFFF
}

/// Unfolded sum of the pseudo-header of `packet` for a transport length `l4_len`.
fn pseudo_sum(packet: &[u8], v6: bool, proto: u8, l4_len: usize) -> u64 {
    let addrs = if v6 { &packet[8..40] } else { &packet[12..20] };
    sum_words(u64::from(proto) + l4_len as u64, addrs)
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

/// Validates the transport header at the start of `l4` and returns its length.
fn transport_header_len(l4: &[u8], proto: u8) -> Option<usize> {
    let len = if proto == TCP {
        let offset = l4.get(12)?;
        let len = usize::from(offset >> 4) * 4;
        if len < TCP_HDR {
            return None;
        }
        len
    } else {
        UDP_HDR
    };
    if l4.len() < len {
        return None;
    }
    Some(len)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use nsplane::{PacketBatch, PacketPool};
    use nsplane_packet::checksum::{
        internet_checksum, transport_checksum_v4, transport_checksum_v6,
    };
    use nsplane_packet::vnet::{OffloadError, segment};

    use super::*;

    const TCP_FIN: u8 = 0x01;
    const TCP_CWR: u8 = 0x80;

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
    fn random_input_never_panics() {
        let packet = build(&spec(false, TCP), &payload(0, 3000));
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..2000 {
            let cut = usize::try_from(next() % (packet.len() as u64 + 1)).unwrap();
            let mut packet = packet[..cut].to_vec();
            for _ in 0..4 {
                let r = next();
                if let Some(byte) = packet.get_mut(usize::try_from(r % 64).unwrap()) {
                    *byte = r.to_le_bytes()[7];
                }
            }
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
    fn ipv4_with_twenty_option_bytes_is_not_merged() {
        for proto in [TCP, UDP] {
            let mut s = spec(false, proto);
            // IHL 10: the length of an IPv6 header.
            s.ip_options = vec![1; 19];
            s.ip_options.push(0);
            assert_eq!(s.ip_len(), 40);
            let packets = flow(&s, &[300; 3]);
            for p in &packets {
                assert!(checksum_valid(p, false, 40, proto), "proto {proto}");
            }
            let (_, _, layout) = coalesce(true, &packets);
            assert_eq!(layout, [vec![0], vec![1], vec![2]], "proto {proto}");
        }
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
