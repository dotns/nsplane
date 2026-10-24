//! Virtio-net header handling for frames read from a packet socket: partial checksums are
//! completed in place, GSO frames are split into frames with
//! [`nsplane_packet::vnet::segment`].

use nsplane::{MAX_BATCH, PacketBatch, PacketBuf, PacketPool};
use nsplane_packet::checksum::{fold, sum_words};
use nsplane_packet::vnet::{OffloadError, VirtioNetHdr, segment};

use crate::frame::HEADER_LEN;

/// IP protocol number of UDP.
const UDP: u8 = 17;

/// The frames split from one GSO frame, handed out one per read.
#[derive(Debug)]
pub(crate) struct Segments {
    /// The GSO frame, ethernet header included.
    frame: Vec<u8>,
    /// Its virtio-net header with the offsets counted from the IP header.
    hdr: VirtioNetHdr,
    /// The index of the segment to produce next once `ready` is empty.
    next: Option<usize>,
    /// IP packets ready to hand out, the next one last.
    ready: Vec<PacketBuf>,
    batch: PacketBatch,
    pool: PacketPool,
}

impl Default for Segments {
    fn default() -> Self {
        Self {
            frame: Vec::new(),
            hdr: VirtioNetHdr::default(),
            next: None,
            ready: Vec::new(),
            batch: PacketBatch::new(),
            pool: PacketPool::new(MAX_BATCH),
        }
    }
}

impl Segments {
    /// Copies the next pending frame into `buf` (at least the GSO frame's length) and
    /// returns its length.
    pub(crate) fn next(&mut self, buf: &mut [u8]) -> Option<usize> {
        loop {
            if let Some(packet) = self.ready.pop() {
                let len = HEADER_LEN + packet.len();
                buf[..HEADER_LEN].copy_from_slice(&self.frame[..HEADER_LEN]);
                buf[HEADER_LEN..len].copy_from_slice(packet.as_packet());
                self.pool.put(packet);
                return Some(len);
            }
            let first = self.next.take()?;
            if self.fill(first).is_err() {
                return None;
            }
        }
    }

    /// Takes over the GSO `frame` behind `hdr` and splits its first batch of segments.
    fn start(&mut self, hdr: &VirtioNetHdr, frame: &[u8]) -> Result<(), OffloadError> {
        self.ready.clear();
        self.frame.clear();
        self.frame.extend_from_slice(frame);
        let from_ip = |offset: u16| {
            u16::try_from(usize::from(offset).saturating_sub(HEADER_LEN)).unwrap_or_default()
        };
        self.hdr = VirtioNetHdr {
            hdr_len: from_ip(hdr.hdr_len),
            csum_start: from_ip(hdr.csum_start),
            ..*hdr
        };
        self.fill(0)
    }

    /// Splits the segments from index `first` on that fit into one batch.
    fn fill(&mut self, first: usize) -> Result<(), OffloadError> {
        let packet = &self.frame[HEADER_LEN..];
        self.next = segment(&self.hdr, packet, first, 0, &mut self.pool, &mut self.batch)?;
        self.ready.extend(self.batch.drain());
        self.ready.reverse();
        Ok(())
    }
}

/// Handles the `len`-byte frame at the front of `buf` behind `hdr`.
///
/// Returns the length of the frame to hand on, with its checksum completed in place if it
/// is partial, or `None` when it is a GSO frame whose frames now wait in `segments`.
pub(crate) fn process(
    hdr: &VirtioNetHdr,
    buf: &mut [u8],
    len: usize,
    segments: &mut Segments,
) -> Result<Option<usize>, OffloadError> {
    let frame = &mut buf[..len];
    if hdr.gso_type != VirtioNetHdr::GSO_NONE {
        if frame.len() < HEADER_LEN {
            return Err(OffloadError::Truncated);
        }
        segments.start(hdr, frame)?;
        return Ok(None);
    }
    if hdr.flags & VirtioNetHdr::F_NEEDS_CSUM != 0 {
        complete_checksum(
            frame,
            usize::from(hdr.csum_start),
            usize::from(hdr.csum_offset),
        )?;
    }
    Ok(Some(len))
}

/// Completes the partial checksum of `frame`: the field at `start + offset` holds the
/// pseudo-header sum, and the checksum covers everything from `start` to the end. A UDP
/// checksum that comes out as 0 is sent as `0xFFFF`, since 0 means none.
fn complete_checksum(frame: &mut [u8], start: usize, offset: usize) -> Result<(), OffloadError> {
    let field = start + offset;
    if field + 2 > frame.len() {
        return Err(OffloadError::BadChecksumOffset);
    }
    let mut csum = !fold(sum_words(0, &frame[start..]));
    if csum == 0 && l4_protocol(frame) == Some(UDP) {
        csum = 0xFFFF;
    }
    frame[field..field + 2].copy_from_slice(&csum.to_be_bytes());
    Ok(())
}

/// The transport protocol of an IPv4 or IPv6 frame (IPv6 without extension headers).
fn l4_protocol(frame: &[u8]) -> Option<u8> {
    match frame.get(12..14)? {
        [0x08, 0x00] => frame.get(HEADER_LEN + 9).copied(),
        [0x86, 0xDD] => frame.get(HEADER_LEN + 6).copied(),
        _ => None,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use nsplane_packet::checksum::{
        internet_checksum, transport_checksum_v4, transport_checksum_v6,
    };

    use super::*;
    use crate::transport::MAX_FRAME_LEN;

    const SRC4: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);
    const DST4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const SRC6: Ipv6Addr = Ipv6Addr::new(0xfd00, 1, 0, 0, 0, 0, 0, 0x15);
    const DST6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    const TCP: u8 = 6;

    /// An ethernet header from the guest to the gateway for `ethertype`.
    fn eth(ethertype: u16) -> Vec<u8> {
        let mut f = vec![0x02, 0, 0, 0, 0, 1, 0x52, 0x54, 0, 0x12, 0x34, 0x56];
        f.extend_from_slice(&ethertype.to_be_bytes());
        f
    }

    /// The pseudo-header sum a guest leaves in the checksum field of a partial-checksum
    /// packet for `l4_len` transport bytes.
    fn partial(v6: bool, proto: u8, l4_len: usize) -> u16 {
        let zeros = vec![0; l4_len];
        if v6 {
            !transport_checksum_v6(SRC6, DST6, proto, &zeros)
        } else {
            !transport_checksum_v4(SRC4, DST4, proto, &zeros)
        }
    }

    /// A TCP over IPv4 GSO frame with `len` payload bytes split at `gso_size`, as a guest
    /// with segmentation offload sends it: lengths of the whole frame, partial checksum.
    pub(crate) fn tcp4_gso_frame(len: usize, gso_size: u16) -> (VirtioNetHdr, Vec<u8>) {
        let mut f = eth(0x0800);
        let total = u16::try_from(40 + len).unwrap();
        f.extend_from_slice(&[0x45, 0]);
        f.extend_from_slice(&total.to_be_bytes());
        f.extend_from_slice(&[0x12, 0x34, 0x40, 0, 64, TCP, 0, 0]);
        f.extend_from_slice(&SRC4.octets());
        f.extend_from_slice(&DST4.octets());
        let csum = internet_checksum(&f[14..34]);
        f[24..26].copy_from_slice(&csum.to_be_bytes());
        f.extend_from_slice(&40000u16.to_be_bytes());
        f.extend_from_slice(&443u16.to_be_bytes());
        f.extend_from_slice(&1000u32.to_be_bytes());
        f.extend_from_slice(&7u32.to_be_bytes());
        f.extend_from_slice(&[5 << 4, 0x18]);
        f.extend_from_slice(&512u16.to_be_bytes());
        f.extend_from_slice(&partial(false, TCP, 20 + len).to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.extend((0..len).map(|i| i.to_le_bytes()[0]));
        let hdr = VirtioNetHdr {
            flags: VirtioNetHdr::F_NEEDS_CSUM,
            gso_type: VirtioNetHdr::GSO_TCPV4,
            hdr_len: 54,
            gso_size,
            csum_start: 34,
            csum_offset: 16,
        };
        (hdr, f)
    }

    /// A UDP over IPv6 frame with a partial checksum and `payload`.
    pub(crate) fn udp6_partial_frame(payload: &[u8]) -> (VirtioNetHdr, Vec<u8>) {
        let mut f = eth(0x86DD);
        let l4_len = 8 + payload.len();
        f.extend_from_slice(&[0x60, 0, 0, 0]);
        f.extend_from_slice(&u16::try_from(l4_len).unwrap().to_be_bytes());
        f.extend_from_slice(&[UDP, 64]);
        f.extend_from_slice(&SRC6.octets());
        f.extend_from_slice(&DST6.octets());
        f.extend_from_slice(&5353u16.to_be_bytes());
        f.extend_from_slice(&53u16.to_be_bytes());
        f.extend_from_slice(&u16::try_from(l4_len).unwrap().to_be_bytes());
        f.extend_from_slice(&partial(true, UDP, l4_len).to_be_bytes());
        f.extend_from_slice(payload);
        let hdr = VirtioNetHdr {
            flags: VirtioNetHdr::F_NEEDS_CSUM,
            csum_start: 54,
            csum_offset: 6,
            ..VirtioNetHdr::default()
        };
        (hdr, f)
    }

    /// Asserts the IP lengths and the IP and transport checksums of an IPv4 or IPv6 frame.
    pub(crate) fn assert_valid(frame: &[u8]) {
        let ip = &frame[HEADER_LEN..];
        if ip[0] >> 4 == 4 {
            assert_eq!(usize::from(u16::from_be_bytes([ip[2], ip[3]])), ip.len());
            assert_eq!(internet_checksum(&ip[..20]), 0, "IPv4 header checksum");
            assert_eq!(transport_checksum_v4(SRC4, DST4, ip[9], &ip[20..]), 0);
        } else {
            assert_eq!(
                usize::from(u16::from_be_bytes([ip[4], ip[5]])) + 40,
                ip.len()
            );
            assert_eq!(transport_checksum_v6(SRC6, DST6, ip[6], &ip[40..]), 0);
        }
    }

    /// Runs `frame` through [`process`] and collects every frame handed on.
    fn run(hdr: &VirtioNetHdr, frame: &[u8]) -> Result<Vec<Vec<u8>>, OffloadError> {
        let mut segments = Segments::default();
        let mut buf = vec![0; MAX_FRAME_LEN];
        buf[..frame.len()].copy_from_slice(frame);
        let mut out = Vec::new();
        if let Some(len) = process(hdr, &mut buf, frame.len(), &mut segments)? {
            out.push(buf[..len].to_vec());
        }
        while let Some(len) = segments.next(&mut buf) {
            out.push(buf[..len].to_vec());
        }
        Ok(out)
    }

    #[test]
    fn plain_frames_pass_unchanged() {
        let (_, frame) = tcp4_gso_frame(100, 1000);
        assert_eq!(run(&VirtioNetHdr::default(), &frame).unwrap(), [frame]);
    }

    #[test]
    fn completes_partial_checksums() {
        let (hdr, frame) = udp6_partial_frame(b"query");
        let out = run(&hdr, &frame).unwrap();
        assert_eq!(out.len(), 1);
        assert_valid(&out[0]);
        assert_eq!(out[0][..60], frame[..60]);
        assert_eq!(out[0][62..], frame[62..]);

        let (mut hdr, frame) = tcp4_gso_frame(300, 1000);
        hdr.gso_type = VirtioNetHdr::GSO_NONE;
        let out = run(&hdr, &frame).unwrap();
        assert_eq!(out.len(), 1);
        assert_valid(&out[0]);
    }

    /// A UDP checksum that computes to 0 is sent as `0xFFFF`.
    #[test]
    fn udp_checksum_zero_becomes_ffff() {
        let (hdr, mut frame) = udp6_partial_frame(&[0xAB, 0xCD, 0, 0]);
        let mut done = frame.clone();
        complete_checksum(&mut done, 54, 6).unwrap();
        // Two payload bytes holding the checksum make the sum all ones.
        let len = frame.len();
        frame[len - 2..].copy_from_slice(&done[60..62]);
        let out = run(&hdr, &frame).unwrap();
        assert_eq!(out[0][60..62], [0xFF, 0xFF]);
        assert_valid(&out[0]);
    }

    #[test]
    fn splits_gso_frames() {
        let (hdr, frame) = tcp4_gso_frame(2500, 1000);
        let out = run(&hdr, &frame).unwrap();
        assert_eq!(out.len(), 3);
        let mut offset = 0;
        for (i, f) in out.iter().enumerate() {
            assert_valid(f);
            assert_eq!(f[..HEADER_LEN], frame[..HEADER_LEN]);
            let payload = &f[54..];
            assert_eq!(payload.len(), if i == 2 { 500 } else { 1000 });
            assert_eq!(payload, &frame[54 + offset..54 + offset + payload.len()]);
            let seq = u32::from_be_bytes(f[38..42].try_into().unwrap());
            assert_eq!(seq, 1000 + u32::try_from(offset).unwrap());
            offset += payload.len();
        }
        // PSH only on the last segment.
        assert_eq!(out[0][47], 0x10);
        assert_eq!(out[2][47], 0x18);
    }

    /// More segments than one batch holds are all handed out, in order.
    #[test]
    fn splits_beyond_one_batch() {
        let (hdr, frame) = tcp4_gso_frame(100 * 70 + 5, 100);
        let out = run(&hdr, &frame).unwrap();
        assert_eq!(out.len(), 71);
        for (i, f) in out.iter().enumerate() {
            assert_valid(f);
            let seq = u32::from_be_bytes(f[38..42].try_into().unwrap());
            assert_eq!(seq, 1000 + 100 * u32::try_from(i).unwrap());
        }
    }

    /// A new GSO frame replaces what is left of the previous one.
    #[test]
    fn a_new_gso_frame_replaces_the_rest() {
        let (hdr, frame) = tcp4_gso_frame(3000, 1000);
        let mut segments = Segments::default();
        let mut buf = vec![0; MAX_FRAME_LEN];
        buf[..frame.len()].copy_from_slice(&frame);
        assert_eq!(
            process(&hdr, &mut buf, frame.len(), &mut segments),
            Ok(None)
        );
        assert!(segments.next(&mut buf).is_some());
        let (hdr, frame) = tcp4_gso_frame(1500, 1000);
        buf[..frame.len()].copy_from_slice(&frame);
        assert_eq!(
            process(&hdr, &mut buf, frame.len(), &mut segments),
            Ok(None)
        );
        assert_eq!(segments.next(&mut buf), Some(54 + 1000));
        assert_eq!(segments.next(&mut buf), Some(54 + 500));
        assert_eq!(segments.next(&mut buf), None);
    }

    #[test]
    fn rejects_malformed_frames() {
        let (hdr, frame) = udp6_partial_frame(b"x");
        let bad = VirtioNetHdr {
            csum_start: u16::try_from(frame.len()).unwrap(),
            ..hdr
        };
        assert_eq!(run(&bad, &frame), Err(OffloadError::BadChecksumOffset));

        let (hdr, frame) = tcp4_gso_frame(3000, 1000);
        assert_eq!(run(&hdr, &frame[..10]), Err(OffloadError::Truncated));
        assert_eq!(run(&hdr, &frame[..40]), Err(OffloadError::Truncated));
        let ufo = VirtioNetHdr { gso_type: 3, ..hdr };
        assert_eq!(run(&ufo, &frame), Err(OffloadError::UnsupportedGso));
        let v6 = VirtioNetHdr {
            gso_type: VirtioNetHdr::GSO_TCPV6,
            ..hdr
        };
        assert_eq!(run(&v6, &frame), Err(OffloadError::BadHeaders));
    }
}
