//! Packet buffers with reserved headroom, a buffer pool, and fixed-size batches.

use std::fmt;

use bytes::{Bytes, BytesMut};
use smallvec::SmallVec;

/// Bytes reserved in front of every packet: 16 for the WireGuard data header
/// (`DATA_HEADER_SZ`) plus 16 spare bytes for future transports.
pub const HEADROOM: usize = 32;

/// Maximum number of packets in a [`PacketBatch`].
pub const MAX_BATCH: usize = 64;

/// A requested range does not fit the packet or its headroom.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundsError;

impl fmt::Display for BoundsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("range out of bounds")
    }
}

impl std::error::Error for BoundsError {}

/// An IP packet with reserved headroom in front of it.
///
/// Fresh buffers start with [`HEADROOM`] zeroed bytes of headroom; [`advance`](Self::advance)
/// and [`reserve_front`](Self::reserve_front) move the packet start in O(1).
///
/// Invariant: `start <= buf.len()`; bytes `[0, start)` are headroom and
/// bytes `[start, buf.len())` are the packet.
#[derive(Debug, Clone)]
pub struct PacketBuf {
    buf: BytesMut,
    start: usize,
    /// Created by [`from_shared`](Self::from_shared); never returned to a [`PacketPool`].
    shared: bool,
}

impl PacketBuf {
    /// Creates an empty packet able to hold `capacity` bytes without reallocating.
    pub fn with_capacity(capacity: usize) -> Self {
        Self::from_storage(BytesMut::with_capacity(HEADROOM + capacity))
    }

    /// Creates a packet holding a copy of `packet`.
    pub fn from_packet(packet: &[u8]) -> Self {
        let mut buf = Self::with_capacity(packet.len());
        buf.buf.extend_from_slice(packet);
        buf
    }

    /// Wraps an empty allocation, filling the headroom with zeros.
    fn from_storage(mut buf: BytesMut) -> Self {
        debug_assert!(buf.is_empty());
        buf.resize(HEADROOM, 0);
        Self {
            buf,
            start: HEADROOM,
            shared: false,
        }
    }

    /// A packet that is `buf[offset..offset + len]` of a buffer that may share its
    /// allocation with others (e.g. one split of a GRO read), without copying.
    ///
    /// No headroom is guaranteed: [`headroom()`](Self::headroom) is `offset`, and bytes
    /// after `offset + len` are truncated away. Opening (decrypting in place; the output
    /// only shrinks) works directly; sealing in place needs headroom the caller must check
    /// with [`headroom()`](Self::headroom). A [`PacketPool`] drops such buffers instead of
    /// pooling them, so they never pin the larger shared allocation.
    ///
    /// # Errors
    ///
    /// Returns [`BoundsError`] if `offset + len` overflows or exceeds `buf.len()`.
    pub fn from_shared(mut buf: BytesMut, offset: usize, len: usize) -> Result<Self, BoundsError> {
        let end = offset.checked_add(len).ok_or(BoundsError)?;
        if end > buf.len() {
            return Err(BoundsError);
        }
        buf.truncate(end);
        Ok(Self {
            buf,
            start: offset,
            shared: true,
        })
    }

    /// The packet bytes.
    pub fn as_packet(&self) -> &[u8] {
        &self.buf[self.start..]
    }

    /// The packet bytes, mutably.
    pub fn as_packet_mut(&mut self) -> &mut [u8] {
        let start = self.start;
        &mut self.buf[start..]
    }

    /// The headroom followed by the packet; `headroom() + len()` bytes.
    pub fn with_headroom_mut(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    /// Packet length in bytes.
    pub fn len(&self) -> usize {
        self.buf.len() - self.start
    }

    /// Bytes in front of the packet.
    pub const fn headroom(&self) -> usize {
        self.start
    }

    /// Drops the first `n` packet bytes by moving the packet start forward, without
    /// copying: the headroom grows by `n` and the packet shrinks by `n`.
    ///
    /// # Errors
    ///
    /// Returns [`BoundsError`] if `n > len()`; the packet is left unchanged.
    pub fn advance(&mut self, n: usize) -> Result<(), BoundsError> {
        if n > self.len() {
            return Err(BoundsError);
        }
        self.start += n;
        Ok(())
    }

    /// Grows the packet at the front by `n` bytes taken from the headroom, without
    /// copying; the exposed bytes keep whatever they held.
    ///
    /// # Errors
    ///
    /// Returns [`BoundsError`] if `n > headroom()`; the packet is left unchanged.
    pub fn reserve_front(&mut self, n: usize) -> Result<(), BoundsError> {
        self.start = self.start.checked_sub(n).ok_or(BoundsError)?;
        Ok(())
    }

    /// Whether the packet is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Packet bytes that fit without reallocating.
    pub fn capacity(&self) -> usize {
        self.buf.capacity() - self.start
    }

    /// Resizes the packet; growing zero-fills, shrinking truncates.
    pub fn set_len(&mut self, len: usize) {
        self.buf.resize(self.start + len, 0);
    }

    /// The packet bytes without the headroom, without copying.
    pub fn into_bytes(self) -> BytesMut {
        let mut buf = self.buf;
        buf.split_off(self.start)
    }

    /// The packet bytes as immutable [`Bytes`], without copying.
    pub fn freeze(self) -> Bytes {
        self.into_bytes().freeze()
    }
}

/// A single-owner pool that reuses packet allocations.
#[derive(Debug, Default)]
pub struct PacketPool {
    free: Vec<BytesMut>,
    max_free: usize,
}

impl PacketPool {
    /// Creates a pool that keeps at most `max_free` idle buffers.
    pub const fn new(max_free: usize) -> Self {
        Self {
            free: Vec::new(),
            max_free,
        }
    }

    /// Returns an empty packet with `capacity() >= capacity`, reusing an idle buffer if any.
    pub fn get(&mut self, capacity: usize) -> PacketBuf {
        let needed = HEADROOM + capacity;
        let storage = self.free.pop().map_or_else(
            || BytesMut::with_capacity(needed),
            |mut buf| {
                buf.clear();
                buf.reserve(needed);
                buf
            },
        );
        PacketBuf::from_storage(storage)
    }

    /// Returns a packet of `len` bytes, reusing an idle buffer if any.
    ///
    /// The packet bytes are unspecified: a reused buffer keeps the bytes it already held
    /// and zero-fills only the bytes it never initialized, so getting the same length again
    /// writes nothing. Use it for a buffer that is written to before it is read, e.g. one a
    /// handshake message is formatted into.
    pub fn get_len(&mut self, len: usize) -> PacketBuf {
        let needed = HEADROOM + len;
        let mut buf = self
            .free
            .pop()
            .unwrap_or_else(|| BytesMut::with_capacity(needed));
        // Shrinking truncates, growing zero-fills only the new bytes.
        buf.resize(needed, 0);
        PacketBuf {
            buf,
            start: HEADROOM,
            shared: false,
        }
    }

    /// Returns a buffer to the pool, or drops it if the pool already holds `max_free`.
    ///
    /// Buffers created by [`PacketBuf::from_shared`] are always dropped. A pooled buffer keeps
    /// its bytes for [`get_len`](Self::get_len).
    pub fn put(&mut self, buf: PacketBuf) {
        if !buf.shared && self.free.len() < self.max_free {
            self.free.push(buf.buf);
        }
    }

    /// Number of idle buffers held by the pool.
    pub const fn free_len(&self) -> usize {
        self.free.len()
    }
}

/// Up to [`MAX_BATCH`] packets, stored inline.
#[derive(Debug, Default)]
pub struct PacketBatch {
    packets: SmallVec<[PacketBuf; MAX_BATCH]>,
}

impl PacketBatch {
    /// Creates an empty batch.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a packet, or hands it back if the batch is full.
    pub fn push(&mut self, packet: PacketBuf) -> Result<(), PacketBuf> {
        if self.is_full() {
            return Err(packet);
        }
        self.packets.push(packet);
        Ok(())
    }

    /// Number of packets in the batch.
    pub fn len(&self) -> usize {
        self.packets.len()
    }

    /// Whether the batch holds no packets.
    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    /// Whether the batch holds [`MAX_BATCH`] packets.
    pub fn is_full(&self) -> bool {
        self.packets.len() == MAX_BATCH
    }

    /// Removes all packets.
    pub fn clear(&mut self) {
        self.packets.clear();
    }

    /// Iterates over the packets in push order.
    pub fn iter(&self) -> impl Iterator<Item = &PacketBuf> {
        self.packets.iter()
    }

    /// Iterates mutably over the packets in push order.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut PacketBuf> {
        self.packets.iter_mut()
    }

    /// Removes and yields all packets in push order.
    pub fn drain(&mut self) -> impl Iterator<Item = PacketBuf> + '_ {
        self.packets.drain(..)
    }
}

impl IntoIterator for PacketBatch {
    type Item = PacketBuf;
    type IntoIter = smallvec::IntoIter<[PacketBuf; MAX_BATCH]>;

    fn into_iter(self) -> Self::IntoIter {
        self.packets.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headroom_precedes_packet() {
        let packet = [1u8, 2, 3, 4, 5];
        let mut buf = PacketBuf::from_packet(&packet);
        let sealer = buf.with_headroom_mut();
        assert_eq!(sealer.len(), HEADROOM + packet.len());
        assert_eq!(&sealer[HEADROOM..], packet);
        sealer[..HEADROOM].fill(0xAA);
        assert_eq!(buf.as_packet(), packet);
        assert_eq!(buf.len(), packet.len());
    }

    #[test]
    fn as_packet_mut_writes_packet() {
        let mut buf = PacketBuf::from_packet(&[0; 4]);
        buf.as_packet_mut()[1] = 9;
        assert_eq!(buf.as_packet(), [0, 9, 0, 0]);
        assert_eq!(buf.with_headroom_mut()[HEADROOM + 1], 9);
    }

    #[test]
    fn set_len_grows_and_shrinks() {
        let mut buf = PacketBuf::from_packet(&[7, 7]);
        buf.set_len(5);
        assert_eq!(buf.as_packet(), [7, 7, 0, 0, 0]);
        buf.set_len(1);
        assert_eq!(buf.as_packet(), [7]);
        buf.set_len(0);
        assert!(buf.is_empty());
        assert_eq!(buf.with_headroom_mut().len(), HEADROOM);
    }

    #[test]
    fn with_capacity_is_empty() {
        let buf = PacketBuf::with_capacity(1500);
        assert_eq!(buf.len(), 0);
        assert!(buf.is_empty());
        assert!(buf.capacity() >= 1500);
    }

    #[test]
    fn freeze_and_into_bytes_yield_packet() {
        let packet = b"hello packet";
        assert_eq!(&PacketBuf::from_packet(packet).freeze()[..], packet);
        assert_eq!(&PacketBuf::from_packet(packet).into_bytes()[..], packet);
        assert!(PacketBuf::with_capacity(8).freeze().is_empty());
    }

    #[test]
    fn pool_reuses_allocation() {
        let mut pool = PacketPool::new(4);
        let mut buf = pool.get(1500);
        let ptr = buf.with_headroom_mut().as_ptr();
        let capacity = buf.capacity();
        buf.set_len(100);
        pool.put(buf);
        assert_eq!(pool.free_len(), 1);

        let mut buf = pool.get(1500);
        assert_eq!(pool.free_len(), 0);
        assert_eq!(buf.with_headroom_mut().as_ptr(), ptr);
        assert_eq!(buf.capacity(), capacity);
        assert!(buf.is_empty());
    }

    #[test]
    fn pool_drops_beyond_max_free() {
        let mut pool = PacketPool::new(2);
        for _ in 0..3 {
            pool.put(PacketBuf::with_capacity(16));
        }
        assert_eq!(pool.free_len(), 2);

        let mut empty = PacketPool::default();
        empty.put(PacketBuf::with_capacity(16));
        assert_eq!(empty.free_len(), 0);
    }

    #[test]
    fn pool_grows_small_buffer() {
        let mut pool = PacketPool::new(1);
        pool.put(PacketBuf::with_capacity(16));
        let buf = pool.get(9000);
        assert!(buf.capacity() >= 9000);
        assert!(buf.is_empty());
        assert_eq!(pool.free_len(), 0);
    }

    #[test]
    fn pool_allocates_when_empty() {
        let mut pool = PacketPool::new(1);
        let buf = pool.get(1500);
        assert!(buf.capacity() >= 1500);
        assert!(buf.is_empty());
    }

    #[test]
    fn advance_and_reserve_front_round_trip() {
        let packet = [1u8, 2, 3, 4, 5, 6];
        let mut buf = PacketBuf::from_packet(&packet);
        assert_eq!(buf.headroom(), HEADROOM);
        let ptr = buf.as_packet().as_ptr();

        buf.advance(2).unwrap();
        assert_eq!(buf.as_packet(), [3, 4, 5, 6]);
        assert_eq!(buf.len(), 4);
        assert_eq!(buf.headroom(), HEADROOM + 2);
        assert_eq!(buf.as_packet().as_ptr(), ptr.wrapping_add(2));

        buf.reserve_front(2).unwrap();
        assert_eq!(buf.as_packet(), packet);
        assert_eq!(buf.headroom(), HEADROOM);
        assert_eq!(buf.as_packet().as_ptr(), ptr);

        buf.reserve_front(HEADROOM).unwrap();
        assert_eq!(buf.headroom(), 0);
        assert_eq!(buf.len(), HEADROOM + packet.len());
        assert_eq!(&buf.as_packet()[HEADROOM..], packet);
        assert_eq!(buf.as_packet().as_ptr(), ptr.wrapping_sub(HEADROOM));
    }

    #[test]
    fn advance_whole_packet_is_empty() {
        let mut buf = PacketBuf::from_packet(&[1, 2, 3]);
        buf.advance(3).unwrap();
        assert!(buf.is_empty());
        assert_eq!(buf.headroom(), HEADROOM + 3);
    }

    #[test]
    fn advance_beyond_len_fails_unchanged() {
        let mut buf = PacketBuf::from_packet(&[1, 2, 3]);
        assert_eq!(buf.advance(4), Err(BoundsError));
        assert_eq!(buf.as_packet(), [1, 2, 3]);
        assert_eq!(buf.headroom(), HEADROOM);
    }

    #[test]
    fn reserve_front_beyond_headroom_fails_unchanged() {
        let mut buf = PacketBuf::from_packet(&[1]);
        assert_eq!(buf.reserve_front(HEADROOM + 1), Err(BoundsError));
        assert_eq!(buf.as_packet(), [1]);
        assert_eq!(buf.headroom(), HEADROOM);
        assert_eq!(BoundsError.to_string(), "range out of bounds");
    }

    #[test]
    fn set_len_into_bytes_freeze_after_advance() {
        let mut buf = PacketBuf::from_packet(&[1, 2, 3, 4]);
        buf.advance(1).unwrap();
        assert!(buf.capacity() >= 3);
        buf.set_len(5);
        assert_eq!(buf.as_packet(), [2, 3, 4, 0, 0]);
        buf.set_len(2);
        assert_eq!(buf.as_packet(), [2, 3]);
        assert_eq!(buf.with_headroom_mut().len(), buf.headroom() + buf.len());
        assert_eq!(&buf.clone().into_bytes()[..], [2, 3]);
        assert_eq!(&buf.freeze()[..], [2, 3]);
    }

    #[test]
    fn with_headroom_mut_after_advance() {
        let mut buf = PacketBuf::from_packet(&[1, 2, 3, 4]);
        buf.advance(3).unwrap();
        let headroom = buf.headroom();
        let whole = buf.with_headroom_mut();
        assert_eq!(whole.len(), headroom + 1);
        assert_eq!(&whole[HEADROOM..], [1, 2, 3, 4]);
    }

    #[test]
    fn from_shared_shares_allocation() {
        let mut whole = BytesMut::with_capacity(64);
        whole.extend(0..64u8);
        let base = whole.as_ptr();
        let first = whole.split_to(40);

        let buf = PacketBuf::from_shared(first, 8, 16).unwrap();
        assert_eq!(buf.headroom(), 8);
        assert_eq!(buf.len(), 16);
        assert_eq!(buf.as_packet(), (8..24u8).collect::<Vec<_>>());
        assert_eq!(buf.as_packet().as_ptr(), base.wrapping_add(8));
        assert_eq!(&buf.freeze()[..], (8..24u8).collect::<Vec<_>>());

        let mut second = PacketBuf::from_shared(whole, 0, 10).unwrap();
        assert_eq!(second.headroom(), 0);
        assert_eq!(second.as_packet(), (40..50u8).collect::<Vec<_>>());
        assert_eq!(second.as_packet().as_ptr(), base.wrapping_add(40));
        assert_eq!(second.with_headroom_mut().len(), 10);
    }

    #[test]
    fn from_shared_out_of_bounds_fails() {
        let mut whole = BytesMut::new();
        whole.extend_from_slice(&[0; 8]);
        assert!(PacketBuf::from_shared(whole.clone(), 4, 4).is_ok());
        assert_eq!(
            PacketBuf::from_shared(whole.clone(), 4, 5).unwrap_err(),
            BoundsError
        );
        assert_eq!(
            PacketBuf::from_shared(whole.clone(), usize::MAX, 1).unwrap_err(),
            BoundsError
        );
        assert_eq!(
            PacketBuf::from_shared(whole, 1, usize::MAX).unwrap_err(),
            BoundsError
        );
    }

    #[test]
    fn pool_drops_shared_and_reuses_normal() {
        let mut pool = PacketPool::new(4);
        let mut whole = BytesMut::new();
        whole.extend_from_slice(&[0; 64]);
        pool.put(PacketBuf::from_shared(whole, 0, 64).unwrap());
        assert_eq!(pool.free_len(), 0);

        let mut buf = pool.get(1500);
        let ptr = buf.with_headroom_mut().as_ptr();
        buf.set_len(10);
        buf.advance(4).unwrap();
        pool.put(buf);
        assert_eq!(pool.free_len(), 1);

        let mut buf = pool.get(1500);
        assert_eq!(buf.headroom(), HEADROOM);
        assert!(buf.is_empty());
        assert_eq!(buf.with_headroom_mut(), [0; HEADROOM]);
        assert_eq!(buf.with_headroom_mut().as_ptr(), ptr);
    }

    #[test]
    fn get_len_keeps_initialized_bytes() {
        let mut pool = PacketPool::new(1);
        let mut buf = pool.get_len(100);
        assert_eq!(buf.len(), 100);
        assert_eq!(buf.headroom(), HEADROOM);
        assert!(buf.as_packet().iter().all(|&b| b == 0));
        let ptr = buf.as_packet().as_ptr();
        buf.as_packet_mut().fill(7);
        buf.advance(10).unwrap();
        pool.put(buf);

        // Same allocation, packet start reset, old bytes kept.
        let buf = pool.get_len(50);
        assert_eq!(buf.as_packet().as_ptr(), ptr);
        assert_eq!(buf.headroom(), HEADROOM);
        assert_eq!(buf.as_packet(), [7; 50]);
        pool.put(buf);

        // Truncated bytes count as never initialized: growing zero-fills them.
        let buf = pool.get_len(60);
        assert_eq!(&buf.as_packet()[..50], [7; 50]);
        assert_eq!(&buf.as_packet()[50..], [0; 10]);
        pool.put(buf);

        // `get` still hands out an empty packet with zeroed headroom.
        let mut buf = pool.get(16);
        assert!(buf.is_empty());
        assert_eq!(buf.with_headroom_mut(), [0; HEADROOM]);
        assert_eq!(pool.free_len(), 0);
    }

    #[test]
    fn get_len_drops_shared_and_allocates_when_empty() {
        let mut pool = PacketPool::new(2);
        let mut whole = BytesMut::new();
        whole.extend_from_slice(&[0; 64]);
        pool.put(PacketBuf::from_shared(whole, 0, 64).unwrap());
        assert_eq!(pool.free_len(), 0);

        let buf = pool.get_len(2048);
        assert_eq!(buf.len(), 2048);
        assert!(buf.capacity() >= 2048);
    }

    #[test]
    fn batch_caps_at_max() {
        let mut batch = PacketBatch::new();
        assert!(batch.is_empty());
        for i in 0..MAX_BATCH {
            batch
                .push(PacketBuf::from_packet(&[u8::try_from(i).unwrap()]))
                .unwrap();
        }
        assert!(batch.is_full());
        assert_eq!(batch.len(), MAX_BATCH);

        let rejected = batch.push(PacketBuf::from_packet(&[0xEE])).unwrap_err();
        assert_eq!(rejected.as_packet(), [0xEE]);
        assert_eq!(batch.len(), MAX_BATCH);

        assert_eq!(batch.drain().count(), MAX_BATCH);
        assert!(batch.is_empty());
    }

    #[test]
    fn batch_iterates_in_push_order() {
        let mut batch = PacketBatch::new();
        for i in 0..3u8 {
            batch.push(PacketBuf::from_packet(&[i])).unwrap();
        }
        for packet in batch.iter_mut() {
            packet.as_packet_mut()[0] += 10;
        }
        let seen: Vec<u8> = batch.iter().map(|p| p.as_packet()[0]).collect();
        assert_eq!(seen, [10, 11, 12]);

        let drained: Vec<u8> = batch.into_iter().map(|p| p.as_packet()[0]).collect();
        assert_eq!(drained, [10, 11, 12]);
    }

    #[test]
    fn batch_clear() {
        let mut batch = PacketBatch::new();
        batch.push(PacketBuf::with_capacity(0)).unwrap();
        batch.clear();
        assert!(batch.is_empty());
    }
}
