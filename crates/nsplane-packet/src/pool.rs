//! A packet pool shared between threads.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::buf::{PacketBuf, PacketPool, TAILROOM};

/// A bounded free list of packet buffers shared by producers and a source: lossy, never waits.
///
/// Producers [`alloc`](Self::alloc) packets from it; whoever is done with a packet hands the
/// buffer back with [`recycle`](Self::recycle). Clones share the same list.
///
/// - Bounded: it keeps at most `max_free` idle buffers.
/// - Lossy: a list that is full or busy (another thread is in `alloc` or `recycle`) takes
///   nothing; a list that is empty or busy makes `alloc` allocate.
/// - Never waits: the lock is only ever tried, and `alloc` skips it while a hint says the
///   list is empty.
#[derive(Debug, Clone)]
pub struct SharedPacketPool {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    pool: Mutex<PacketPool>,
    max_free: usize,
    /// Whether the pool may hold a buffer; a hint, rechecked under the lock.
    stocked: AtomicBool,
    allocated: AtomicU64,
}

impl SharedPacketPool {
    /// Creates a pool that keeps at most `max_free` idle buffers.
    pub fn new(max_free: usize) -> Self {
        Self {
            inner: Arc::new(Inner {
                pool: Mutex::new(PacketPool::new(max_free)),
                max_free,
                stocked: AtomicBool::new(false),
                allocated: AtomicU64::new(0),
            }),
        }
    }

    /// Returns a packet of `len` bytes behind [`HEADROOM`](crate::HEADROOM), with
    /// `capacity() >= len + TAILROOM`, reusing an idle buffer if one is free.
    ///
    /// The packet bytes are unspecified, so they are to be written before they are read. A
    /// reused buffer that is too small is grown. Without an idle buffer, or while the list is
    /// busy, it allocates a new one, zero-filled to `len`, and counts it in
    /// [`allocated`](Self::allocated).
    pub fn alloc(&self, len: usize) -> PacketBuf {
        let capacity = len + TAILROOM;
        let mut buf = self.take(capacity).unwrap_or_else(|| {
            self.inner.allocated.fetch_add(1, Ordering::Relaxed);
            PacketBuf::with_capacity(capacity)
        });
        buf.set_len(len);
        buf
    }

    /// An idle buffer with room for `capacity` bytes; `None` if the list is empty or busy.
    fn take(&self, capacity: usize) -> Option<PacketBuf> {
        let inner = &*self.inner;
        if !inner.stocked.load(Ordering::Relaxed) {
            return None;
        }
        let mut pool = inner.pool.try_lock().ok()?;
        if pool.free_len() == 0 {
            inner.stocked.store(false, Ordering::Relaxed);
            return None;
        }
        // Grows a recycled buffer that is too small.
        let buf = pool.get(capacity);
        if pool.free_len() == 0 {
            inner.stocked.store(false, Ordering::Relaxed);
        }
        Some(buf)
    }

    /// Takes buffers out of `bufs` until the list holds `max_free` idle ones and leaves the
    /// rest; takes none while the list is busy.
    ///
    /// Buffers created by [`PacketBuf::from_shared`] are taken and dropped.
    pub fn recycle(&self, bufs: &mut Vec<PacketBuf>) {
        let inner = &*self.inner;
        let Ok(mut pool) = inner.pool.try_lock() else {
            return;
        };
        let room = inner.max_free - pool.free_len();
        for buf in bufs.drain(bufs.len().saturating_sub(room)..) {
            pool.put(buf);
        }
        if pool.free_len() > 0 {
            inner.stocked.store(true, Ordering::Relaxed);
        }
    }

    /// Number of idle buffers in the list; 0 while the list is busy.
    pub fn free_len(&self) -> usize {
        self.inner.pool.try_lock().map_or(0, |pool| pool.free_len())
    }

    /// How many buffers [`alloc`](Self::alloc) allocated because none was idle or the list
    /// was busy.
    pub fn allocated(&self) -> u64 {
        self.inner.allocated.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::*;
    use crate::buf::HEADROOM;

    #[test]
    fn alloc_has_headroom_and_tailroom() {
        let pool = SharedPacketPool::new(4);
        for len in [0, 1, 64, 1420] {
            let mut buf = pool.alloc(len);
            assert_eq!(buf.len(), len);
            assert_eq!(buf.headroom(), HEADROOM);
            assert!(buf.capacity() >= len + TAILROOM);
            assert_eq!(buf.with_headroom_mut()[..HEADROOM], [0; HEADROOM]);
        }
        assert_eq!(pool.allocated(), 4);
        assert_eq!(pool.free_len(), 0);
    }

    #[test]
    fn recycled_buffers_are_reused() {
        let pool = SharedPacketPool::new(4);
        let mut first = pool.alloc(1420);
        let addr = first.with_headroom_mut().as_ptr();
        pool.recycle(&mut vec![first]);
        assert_eq!(pool.free_len(), 1);

        let mut second = pool.alloc(100);
        assert_eq!(second.with_headroom_mut().as_ptr(), addr);
        assert_eq!(second.len(), 100);
        assert_eq!(second.headroom(), HEADROOM);
        assert_eq!(pool.allocated(), 1);
        assert_eq!(pool.free_len(), 0);
        assert!(!pool.inner.stocked.load(Ordering::Relaxed));

        // Empty again: the next one is allocated.
        pool.alloc(100);
        assert_eq!(pool.allocated(), 2);
    }

    #[test]
    fn recycle_takes_up_to_the_bound() {
        let pool = SharedPacketPool::new(2);
        let mut bufs: Vec<_> = (0..3).map(|_| PacketBuf::with_capacity(16)).collect();
        pool.recycle(&mut bufs);
        assert_eq!(bufs.len(), 1);
        assert_eq!(pool.free_len(), 2);
        pool.recycle(&mut bufs);
        assert_eq!(bufs.len(), 1);

        let none = SharedPacketPool::new(0);
        none.recycle(&mut bufs);
        assert_eq!(bufs.len(), 1);
        assert_eq!(none.free_len(), 0);
        assert!(!none.inner.stocked.load(Ordering::Relaxed));
    }

    #[test]
    fn shared_buffers_are_dropped() -> Result<(), crate::BoundsError> {
        let pool = SharedPacketPool::new(2);
        let shared = PacketBuf::from_shared(BytesMut::zeroed(64), 0, 64)?;
        let mut bufs = vec![shared];
        pool.recycle(&mut bufs);
        assert!(bufs.is_empty());
        assert_eq!(pool.free_len(), 0);
        Ok(())
    }

    #[test]
    fn too_small_recycled_buffer_is_grown() {
        let pool = SharedPacketPool::new(1);
        pool.recycle(&mut vec![PacketBuf::with_capacity(8)]);
        let mut buf = pool.alloc(1400);
        assert_eq!(buf.len(), 1400);
        assert_eq!(buf.headroom(), HEADROOM);
        assert!(buf.capacity() >= 1400 + TAILROOM);
        assert_eq!(buf.with_headroom_mut()[..HEADROOM], [0; HEADROOM]);
        assert_eq!(pool.allocated(), 0);
    }

    #[test]
    fn a_busy_list_is_skipped() {
        let pool = SharedPacketPool::new(4);
        pool.recycle(&mut vec![PacketBuf::with_capacity(1600)]);
        let held = pool.inner.pool.lock();
        // Neither side waits: alloc allocates and recycle leaves its buffers.
        let buf = pool.alloc(10);
        assert_eq!(buf.len(), 10);
        assert_eq!(pool.allocated(), 1);
        let mut bufs = vec![PacketBuf::with_capacity(1600)];
        pool.recycle(&mut bufs);
        assert_eq!(bufs.len(), 1);
        assert_eq!(pool.free_len(), 0);
        drop(held);
        assert_eq!(pool.free_len(), 1);
    }

    #[test]
    fn the_hint_skips_an_empty_list() {
        let pool = SharedPacketPool::new(4);
        assert!(!pool.inner.stocked.load(Ordering::Relaxed));
        pool.recycle(&mut Vec::new());
        assert!(!pool.inner.stocked.load(Ordering::Relaxed));
        pool.recycle(&mut vec![PacketBuf::with_capacity(16)]);
        assert!(pool.inner.stocked.load(Ordering::Relaxed));

        // A stale hint is cleared under the lock.
        pool.alloc(1);
        pool.inner.stocked.store(true, Ordering::Relaxed);
        pool.alloc(1);
        assert!(!pool.inner.stocked.load(Ordering::Relaxed));
        assert_eq!(pool.allocated(), 1);
    }

    #[test]
    fn clones_share_the_list() {
        let pool = SharedPacketPool::new(4);
        let other = pool.clone();
        other.recycle(&mut vec![PacketBuf::with_capacity(16)]);
        assert_eq!(pool.free_len(), 1);
        pool.alloc(16);
        assert_eq!(other.free_len(), 0);
        assert_eq!(other.allocated(), 0);
    }
}
