//! A published value readers take whole and writers replace.
//!
//! [`SnapshotCell`] replaces a lock-free `Arc` swap crate whose 1.9 releases can hand a reader
//! a value of another instance, or lose an update, when several instances are replaced
//! concurrently. It uses only `std` locks and reference counts.
//!
//! The cell keeps the current value in 16 cache-line-padded shards, each behind its own
//! `RwLock` and with its own reference count, so readers on different cores do not write to
//! one shared cache line. [`SnapshotCell::load`] read-locks the shard of its thread only to
//! clone that shard's reference and releases the lock before it returns: a loaded
//! [`Snapshot`] holds no lock, never blocks a writer, and may be kept across other locks and
//! other loads. A writer allocates one reference per shard, then takes every shard's write
//! lock in shard order and replaces them, so [`SnapshotCell::store`] costs 16 small
//! allocations and 16 lock round trips and waits only for loads in progress; it returns once
//! no new load can observe the old value. A replaced value lives until its last holder drops
//! it. The locks only guard a pointer swap, so a panic while one is held cannot leave a torn
//! value and poisoning is ignored.

use std::fmt;
use std::ops::Deref;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, PoisonError, RwLock};

/// Shards per cell; threads beyond it share shards.
const SHARDS: usize = 16;

static NEXT_SLOT: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    /// The shard this thread reads in every cell.
    static SLOT: usize = NEXT_SLOT.fetch_add(1, Ordering::Relaxed) % SHARDS;
}

#[repr(align(128))]
struct Shard<T>(RwLock<Arc<Published<T>>>);

/// The published `Arc`, behind a reference count of its shard.
struct Published<T>(Arc<T>);

/// A shared `Arc<T>` that readers load and a writer replaces; see the [module docs](self).
///
/// A loaded value never blocks writers, [`store`](Self::store) returns once no new load can
/// observe the old value, and old values live until their holders drop them. Callers
/// serialize their own writers.
pub struct SnapshotCell<T> {
    shards: [Shard<T>; SHARDS],
}

impl<T> SnapshotCell<T> {
    /// A cell publishing `value`.
    pub fn new(value: impl Into<Arc<T>>) -> Self {
        let value = value.into();
        Self {
            shards: std::array::from_fn(|_| {
                Shard(RwLock::new(Arc::new(Published(Arc::clone(&value)))))
            }),
        }
    }

    /// The current value. It holds no lock: dropping it is a reference count decrement.
    pub fn load(&self) -> Snapshot<T> {
        let slot = SLOT.with(|slot| *slot);
        let shard = self.shards[slot]
            .0
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        Snapshot(Arc::clone(&shard))
    }

    /// The current value as its `Arc`.
    pub fn load_full(&self) -> Arc<T> {
        Arc::clone(&self.load().0.0)
    }

    /// Publishes `value`; returns once no new [`load`](Self::load) can observe the old one.
    pub fn store(&self, value: impl Into<Arc<T>>) {
        let value = value.into();
        let mut values: [Arc<Published<T>>; SHARDS] =
            std::array::from_fn(|_| Arc::new(Published(Arc::clone(&value))));
        let mut shards: [_; SHARDS] = std::array::from_fn(|index| {
            self.shards[index]
                .0
                .write()
                .unwrap_or_else(PoisonError::into_inner)
        });
        for (shard, value) in shards.iter_mut().zip(&mut values) {
            std::mem::swap(&mut **shard, value);
        }
        // Unlock before the old values drop.
        drop(shards);
    }
}

impl<T: Default> Default for SnapshotCell<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: fmt::Debug> fmt::Debug for SnapshotCell<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SnapshotCell").field(&*self.load()).finish()
    }
}

/// A value loaded from a [`SnapshotCell`]; later stores do not change it.
pub struct Snapshot<T>(Arc<Published<T>>);

impl<T> Clone for Snapshot<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<T> Deref for Snapshot<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0.0
    }
}

impl<T: fmt::Debug> fmt::Debug for Snapshot<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

#[cfg(test)]
mod tests;
