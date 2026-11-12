//! Property tests of the virtio-net header handling: the header and the frame behind it come
//! from the guest, so neither is trusted.
//!
//! The cases come from a seeded generator, so every run tests the same inputs.

use nsplane_packet::checksum::internet_checksum;
use nsplane_packet::vnet::{OffloadError, VirtioNetHdr};

use super::tests::{assert_valid, tcp4_gso_frame, udp6_partial_frame};
use super::{Segments, process};
use crate::frame::HEADER_LEN;
use crate::transport::MAX_FRAME_LEN;

/// `SplitMix64`.
struct Rng(u64);

impl Rng {
    const fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
    }

    fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }

    const fn byte(&mut self) -> u8 {
        self.next().to_le_bytes()[0]
    }

    const fn u16(&mut self) -> u16 {
        let b = self.next().to_le_bytes();
        u16::from_le_bytes([b[0], b[1]])
    }

    /// A value up to `small`, or now and then any value.
    fn offset(&mut self, small: usize) -> u16 {
        if self.chance(15) {
            self.u16()
        } else {
            u16::try_from(self.below(small)).unwrap()
        }
    }

    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len())]
    }
}

/// The reader's side of [`process`]: one buffer and one set of segments for every frame.
struct Reader {
    segments: Segments,
    buf: Vec<u8>,
}

impl Reader {
    fn new() -> Self {
        Self {
            segments: Segments::default(),
            buf: vec![0; MAX_FRAME_LEN],
        }
    }

    /// Runs `frame` behind `hdr` through [`process`] and collects every frame handed on.
    fn read(&mut self, hdr: &VirtioNetHdr, frame: &[u8]) -> Result<Vec<Vec<u8>>, OffloadError> {
        self.buf[..frame.len()].copy_from_slice(frame);
        let mut out = Vec::new();
        match process(hdr, &mut self.buf, frame.len(), &mut self.segments) {
            Ok(Some(len)) => out.push(self.buf[..len].to_vec()),
            Ok(None) => {}
            Err(err) => {
                assert_eq!(self.segments.next(&mut self.buf), None);
                return Err(err);
            }
        }
        while let Some(len) = self.segments.next(&mut self.buf) {
            out.push(self.buf[..len].to_vec());
            // Every segment carries at least one byte of the frame.
            assert!(out.len() <= frame.len() + 1, "the segments do not end");
        }
        Ok(out)
    }
}

#[test]
fn a_gso_frame_splits_into_valid_frames_that_carry_its_payload() {
    let mut rng = Rng(0x5eed_e7a1);
    let mut reader = Reader::new();
    for _ in 0..400 {
        let most = if rng.chance(10) { 60_000 } else { 6_000 };
        let len = 1 + rng.below(most);
        let gso_size = u16::try_from(1 + rng.below(1460)).unwrap();
        // Keep the number of segments of a case in the hundreds.
        let gso_size = gso_size.max(u16::try_from(len / 300 + 1).unwrap());
        let (hdr, frame) = tcp4_gso_frame(len, gso_size);
        let frames = reader.read(&hdr, &frame).unwrap();
        assert_eq!(frames.len(), len.div_ceil(usize::from(gso_size)));

        let mut payload = Vec::with_capacity(len);
        for (i, segment) in frames.iter().enumerate() {
            assert_valid(segment);
            assert_eq!(segment[..HEADER_LEN], frame[..HEADER_LEN]);
            let data = &segment[54..];
            let last = i + 1 == frames.len();
            assert!(
                data.len() == usize::from(gso_size) || (last && data.len() < usize::from(gso_size))
            );
            // The sequence number advances with the payload.
            let seq = u32::from_be_bytes(segment[38..42].try_into().unwrap());
            assert_eq!(seq, 1000 + u32::try_from(payload.len()).unwrap());
            payload.extend_from_slice(data);
        }
        assert_eq!(payload, frame[54..]);

        // A frame with a partial checksum comes back whole, with the checksum completed.
        let data: Vec<u8> = (0..rng.below(1400)).map(|_| rng.byte()).collect();
        let (hdr, frame) = udp6_partial_frame(&data);
        let frames = reader.read(&hdr, &frame).unwrap();
        let [completed] = frames.as_slice() else {
            panic!("{} frames", frames.len());
        };
        assert_valid(completed);
        assert_eq!(completed[62..], data);
    }
}

/// A header and a frame from a guest: a valid pair with some fields and bytes changed.
fn untrusted(rng: &mut Rng) -> (VirtioNetHdr, Vec<u8>) {
    let (mut hdr, mut frame) = if rng.chance(60) {
        let gso_size = u16::try_from(1 + rng.below(1460)).unwrap();
        tcp4_gso_frame(rng.below(3000), gso_size)
    } else {
        let data: Vec<u8> = (0..rng.below(200)).map(|_| rng.byte()).collect();
        udp6_partial_frame(&data)
    };
    if rng.chance(30) {
        let any = rng.byte();
        hdr.flags = rng.pick(&[0, VirtioNetHdr::F_NEEDS_CSUM, any]);
    }
    if rng.chance(30) {
        let any = rng.byte();
        hdr.gso_type = rng.pick(&[0, 1, 3, 4, 5, 0x81, 0x84, any]);
    }
    if rng.chance(30) {
        hdr.hdr_len = rng.offset(100);
    }
    if rng.chance(30) {
        hdr.gso_size = rng.offset(1500);
    }
    if rng.chance(30) {
        hdr.csum_start = rng.offset(80);
    }
    if rng.chance(30) {
        hdr.csum_offset = rng.offset(40);
    }
    if rng.chance(40) {
        for _ in 0..=rng.below(2) {
            match rng.below(3) {
                0 if !frame.is_empty() => {
                    let at = rng.below(frame.len().min(80));
                    frame[at] ^= 1 << rng.below(8);
                }
                1 => frame.truncate(rng.below(frame.len().min(80) + 1)),
                _ if !frame.is_empty() => {
                    let at = rng.below(frame.len());
                    frame[at] = rng.byte();
                }
                _ => {}
            }
        }
    }
    (hdr, frame)
}

#[test]
fn an_untrusted_header_is_refused_or_applied_within_the_frame() {
    let mut rng = Rng(0x5eed_e7a2);
    let mut reader = Reader::new();
    let (mut plain, mut completed, mut split, mut refused) = (0, 0, 0, 0);
    for _ in 0..30_000 {
        let (hdr, frame) = untrusted(&mut rng);
        let needs_csum = hdr.flags & VirtioNetHdr::F_NEEDS_CSUM != 0;
        let start = usize::from(hdr.csum_start);
        let field = start + usize::from(hdr.csum_offset);
        let result = reader.read(&hdr, &frame);

        if hdr.gso_type != VirtioNetHdr::GSO_NONE {
            // Split or refused; every frame handed on has the ethernet header of the
            // original and is no longer than it.
            let Ok(frames) = result else {
                refused += 1;
                continue;
            };
            assert!(!frames.is_empty(), "{hdr:?}");
            for segment in &frames {
                assert_eq!(segment[..HEADER_LEN], frame[..HEADER_LEN]);
                assert!(segment.len() <= frame.len(), "{hdr:?}");
            }
            split += 1;
        } else if needs_csum {
            // The checksum field must lie in the frame; nothing else is written.
            if field + 2 > frame.len() {
                assert_eq!(result, Err(OffloadError::BadChecksumOffset), "{hdr:?}");
                refused += 1;
                continue;
            }
            let frames = result.unwrap();
            let [out] = frames.as_slice() else {
                panic!("{} frames", frames.len());
            };
            assert_eq!(out[..field], frame[..field]);
            assert_eq!(out[field + 2..], frame[field + 2..]);
            // The field held the pseudo-header sum: with it, the transport bytes verify.
            if hdr.csum_offset % 2 == 0 {
                let mut summed = frame[field..field + 2].to_vec();
                summed.extend_from_slice(&out[start..]);
                assert_eq!(internet_checksum(&summed), 0, "{hdr:?}");
            }
            completed += 1;
        } else {
            assert_eq!(result, Ok(vec![frame]));
            plain += 1;
        }
    }
    assert!(
        plain > 1_000 && completed > 3_000 && split > 3_000 && refused > 3_000,
        "{plain} {completed} {split} {refused}"
    );
}
