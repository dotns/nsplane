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
//! no new load can observe the old value. Stores are serialized by a writer lock inside the
//! cell, so several threads may store concurrently. A replaced value lives until its last
//! holder drops it. The locks only guard a pointer swap, so a panic while one is held cannot
//! leave a torn value and poisoning is ignored.
//!
//! [`SnapshotCell::read`] lends the value to a closure without a lock or a reference count
//! while it is unchanged. Each store gives the value the next generation of its cell and
//! publishes that generation (Release) after the shards hold the value. Each thread caches
//! the last value it read of up to 8 cells, keyed by a cell id from a global counter (never
//! reused, unlike an address) and the generation. A read loads the generation (Acquire) and
//! uses the cached value when it is of this cell and generation; otherwise it loads the shard
//! and caches its value. A load waits while the shard's generation is above a generation read
//! after it, so neither a load nor a read uses a value before its generation is published, and
//! a value it uses was the published one at some point of the call. So loads and reads never
//! return an older value than a store that returned or an earlier load or read on the same
//! thread saw, and one closure sees one whole value. A read inside the closure of another uses
//! the cache but cannot fill it, and a read while the thread exits loads the shard.
//!
//! Retention: the cache holds at most 8 values per thread across all cells, so at most one
//! replaced value per cell per thread, plus values of dropped cells until they are evicted.
//! Such a value lives until the thread reads that cell again, evicts the entry or exits, and
//! it may drop on that reader thread. A thread that stops reading keeps up to 8 old values
//! until it exits.

use std::any::Any;
use std::cell::RefCell;
use std::fmt;
use std::ops::Deref;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};

/// Shards per cell; threads beyond it share shards.
const SHARDS: usize = 16;

/// Cells whose last read value each thread caches for [`SnapshotCell::read`].
const CACHE_ENTRIES: usize = 8;

static NEXT_SLOT: AtomicUsize = AtomicUsize::new(0);

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

thread_local! {
    /// The shard this thread reads in every cell.
    static SLOT: usize = NEXT_SLOT.fetch_add(1, Ordering::Relaxed) % SHARDS;

    /// The values this thread read last.
    static CACHE: RefCell<Cache> = const {
        RefCell::new(Cache {
            entries: [const { None }; CACHE_ENTRIES],
            next: 0,
        })
    };
}

#[repr(align(128))]
struct Shard<T>(RwLock<Arc<Published<T>>>);

/// The published `Arc` and its generation, behind a reference count of its shard.
struct Published<T> {
    generation: u64,
    value: Arc<T>,
}

/// A value a thread read: its cell, its generation and the value.
struct Entry {
    id: u64,
    generation: u64,
    value: Arc<dyn Any + Send + Sync>,
}

/// A thread's read values, at most one per cell.
struct Cache {
    entries: [Option<Entry>; CACHE_ENTRIES],
    /// The entry the next new cell replaces.
    next: usize,
}

impl Cache {
    /// The cached value of cell `id` at `generation`.
    #[inline]
    fn get<T: 'static>(&self, id: u64, generation: u64) -> Option<&T> {
        self.entries
            .iter()
            .flatten()
            .find(|entry| entry.id == id && entry.generation == generation)
            .and_then(|entry| entry.value.downcast_ref())
    }

    /// Caches `entry` in place of its cell's entry, else of the next one in turn; returns the
    /// replaced entry.
    fn insert(&mut self, entry: Entry) -> Option<Entry> {
        let index = self
            .entries
            .iter()
            .position(|cached| cached.as_ref().is_some_and(|cached| cached.id == entry.id))
            .unwrap_or_else(|| {
                let index = self.next;
                self.next = (index + 1) % CACHE_ENTRIES;
                index
            });
        self.entries[index].replace(entry)
    }
}

/// A shared `Arc<T>` that readers load and writers replace; see the [module docs](self).
///
/// A loaded value never blocks writers, [`store`](Self::store) returns once no new load can
/// observe the old value, and old values live until their holders drop them, including up to
/// one per thread in the cache of [`read`](Self::read). Several threads may store
/// concurrently.
pub struct SnapshotCell<T> {
    shards: [Shard<T>; SHARDS],
    /// The generation of the published value, stored after the shards.
    generation: AtomicU64,
    /// Tells the cells apart in the per-thread cache.
    id: u64,
    /// Serializes stores, so generations are published in the order they are swapped in.
    writer: Mutex<()>,
}

impl<T> SnapshotCell<T> {
    /// A cell publishing `value`.
    pub fn new(value: impl Into<Arc<T>>) -> Self {
        let value = value.into();
        Self {
            shards: std::array::from_fn(|_| {
                Shard(RwLock::new(Arc::new(Published {
                    generation: 0,
                    value: Arc::clone(&value),
                })))
            }),
            generation: AtomicU64::new(0),
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            writer: Mutex::new(()),
        }
    }

    /// The current value. It holds no lock: dropping it is a reference count decrement.
    pub fn load(&self) -> Snapshot<T> {
        let slot = SLOT.with(|slot| *slot);
        loop {
            let published = Arc::clone(
                &self.shards[slot]
                    .0
                    .read()
                    .unwrap_or_else(PoisonError::into_inner),
            );
            if published.generation <= self.generation.load(Ordering::Acquire) {
                return Snapshot(published);
            }
            // A store swapped its value in but has not published its generation yet, so a
            // later read could still return the older value: wait for the publication.
            std::thread::yield_now();
        }
    }

    /// The current value as its `Arc`.
    pub fn load_full(&self) -> Arc<T> {
        Arc::clone(&self.load().0.value)
    }

    /// Publishes `value`; returns once no new [`load`](Self::load) or [`read`](Self::read)
    /// can observe the old one.
    pub fn store(&self, value: impl Into<Arc<T>>) {
        let value = value.into();
        let writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        let generation = self.generation.load(Ordering::Relaxed) + 1;
        let mut values: [Arc<Published<T>>; SHARDS] = std::array::from_fn(|_| {
            Arc::new(Published {
                generation,
                value: Arc::clone(&value),
            })
        });
        let mut shards: [_; SHARDS] = std::array::from_fn(|index| {
            self.shards[index]
                .0
                .write()
                .unwrap_or_else(PoisonError::into_inner)
        });
        for (shard, value) in shards.iter_mut().zip(&mut values) {
            std::mem::swap(&mut **shard, value);
        }
        drop(shards);
        self.generation.store(generation, Ordering::Release);
        // Unlock before the old values drop.
        drop(writer);
    }
}

impl<T: Send + Sync + 'static> SnapshotCell<T> {
    /// Runs `f` on the current value. While the value is unchanged since this thread last
    /// read it, this takes no lock and no reference count.
    ///
    /// The thread's cache keeps the value alive until the thread reads this cell again,
    /// evicts it or exits (see the [module docs](self)). `f` may read cells and store.
    #[inline]
    pub fn read<R>(&self, f: impl FnOnce(&T) -> R) -> R {
        let generation = self.generation.load(Ordering::Acquire);
        let mut f = Some(f);
        if let Ok(Some(result)) =
            CACHE.try_with(|cache| f.take().map(|f| self.read_cached(cache, generation, f)))
        {
            return result;
        }
        // The cache is gone: this thread is exiting.
        f.map_or_else(
            || unreachable!("try_with takes `f` exactly when it returns Ok"),
            |f| f(&self.load()),
        )
    }

    /// Runs `f` on the cached value of `generation`, else on the published one.
    #[inline]
    fn read_cached<R>(
        &self,
        cache: &RefCell<Cache>,
        generation: u64,
        f: impl FnOnce(&T) -> R,
    ) -> R {
        if let Ok(entries) = cache.try_borrow()
            && let Some(value) = entries.get(self.id, generation)
        {
            return f(value);
        }
        f(&self.refill(cache))
    }

    /// Loads the published value and caches it, unless the cache is lent to an outer read
    /// (`f` of a read on this thread).
    #[cold]
    #[inline(never)]
    fn refill(&self, cache: &RefCell<Cache>) -> Arc<T> {
        let published = self.load().0;
        let (generation, value) = (published.generation, Arc::clone(&published.value));
        // The replaced entry drops after the borrow ends: its value's drop may read a cell.
        let _replaced = cache.try_borrow_mut().map(|mut entries| {
            entries.insert(Entry {
                id: self.id,
                generation,
                value: Arc::clone(&value) as Arc<dyn Any + Send + Sync>,
            })
        });
        value
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
        &self.0.value
    }
}

impl<T: fmt::Debug> fmt::Debug for Snapshot<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

#[cfg(test)]
mod tests;
