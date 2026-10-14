use std::sync::Barrier;
use std::sync::atomic::AtomicBool;
use std::thread;
use std::time::{Duration, Instant};

use super::*;

#[test]
fn store_publishes_whole_values() {
    let cell = SnapshotCell::new(1);
    assert_eq!(*cell.load(), 1);
    assert_eq!(*cell.load_full(), 1);
    let value = Arc::new(2);
    cell.store(Arc::clone(&value));
    assert!(Arc::ptr_eq(&cell.load_full(), &value));
    let loaded = cell.load();
    assert_eq!((*loaded, *loaded.clone()), (2, 2));
}

#[test]
fn default_and_debug() {
    let cell: SnapshotCell<Vec<u8>> = SnapshotCell::default();
    assert!(cell.load().is_empty());
    cell.store(vec![7]);
    assert_eq!(format!("{cell:?}"), "SnapshotCell([7])");
    assert_eq!(format!("{:?}", cell.load()), "[7]");
}

#[test]
fn a_held_load_blocks_neither_a_store_nor_another_load() {
    let cell = SnapshotCell::new(1);
    let held = cell.load();
    cell.store(2);
    let again = cell.load();
    assert_eq!((*held, *again), (1, 2));
    cell.store(3);
    assert_eq!((*held, *again, *cell.load()), (1, 2, 3));
}

#[test]
fn a_store_returns_while_another_thread_holds_a_load() {
    let cell = Arc::new(SnapshotCell::new(1));
    let (loaded, stored) = (Arc::new(Barrier::new(2)), Arc::new(Barrier::new(2)));
    let holder = {
        let (cell, loaded, stored) = (Arc::clone(&cell), Arc::clone(&loaded), Arc::clone(&stored));
        thread::spawn(move || {
            let held = cell.load();
            loaded.wait();
            stored.wait();
            (*held, *cell.load())
        })
    };
    loaded.wait();
    cell.store(2);
    stored.wait();
    assert_eq!(holder.join().unwrap(), (1, 2));
}

#[test]
fn readers_on_more_threads_than_shards_see_a_store() {
    let readers = 2 * SHARDS + 1;
    let cell = Arc::new(SnapshotCell::new(0));
    let (loaded, stored) = (
        Arc::new(Barrier::new(readers + 1)),
        Arc::new(Barrier::new(readers + 1)),
    );
    let threads: Vec<_> = (0..readers)
        .map(|_| {
            let (cell, loaded, stored) =
                (Arc::clone(&cell), Arc::clone(&loaded), Arc::clone(&stored));
            thread::spawn(move || {
                let before = *cell.load();
                loaded.wait();
                stored.wait();
                (before, *cell.load())
            })
        })
        .collect();
    loaded.wait();
    cell.store(1);
    stored.wait();
    for thread in threads {
        assert_eq!(thread.join().unwrap(), (0, 1));
    }
}

/// Several cells with values of the same size, so a freed value of one can reuse the address
/// of another's, replaced in a loop while readers on more threads than shards load them: a
/// reader only ever gets its own cell's values, and never an older one than it saw before.
#[test]
fn cells_replaced_under_load_never_mix_or_go_back() {
    const CELLS: u64 = 4;
    const READERS: usize = 4;
    const MAX_STORES: u64 = 2_000_000;
    let deadline = Instant::now() + Duration::from_secs(2);

    let cells: Vec<_> = (0..CELLS)
        .map(|id| Arc::new(SnapshotCell::new((id, 0_u64))))
        .collect();
    let mut threads = Vec::new();
    for (id, cell) in (0..CELLS).zip(&cells) {
        let done = Arc::new(AtomicBool::new(false));
        for _ in 0..READERS {
            let (cell, done) = (Arc::clone(cell), Arc::clone(&done));
            threads.push(thread::spawn(move || {
                let mut held = cell.load();
                let mut count = 0_u64;
                while !done.load(Ordering::Relaxed) {
                    let loaded = cell.load();
                    let ((owner, sequence), (_, last)) = (*loaded, *held);
                    assert_eq!(owner, id, "a value of another cell");
                    assert!(sequence >= last, "{sequence} went back from {last}");
                    // Keep every other value across the next load.
                    if count.is_multiple_of(2) {
                        held = loaded;
                    }
                    count += 1;
                }
            }));
        }
        let (cell, done) = (Arc::clone(cell), Arc::clone(&done));
        threads.push(thread::spawn(move || {
            let mut sequence = 0;
            while sequence < MAX_STORES && Instant::now() < deadline {
                sequence += 1;
                cell.store((id, sequence));
            }
            done.store(true, Ordering::Relaxed);
        }));
    }
    assert!(threads.len() > SHARDS);
    for thread in threads {
        thread.join().unwrap();
    }
    for (id, cell) in (0..CELLS).zip(&cells) {
        let (owner, sequence) = *cell.load();
        assert_eq!(owner, id);
        assert!(sequence > 0);
    }
}

#[test]
fn read_sees_each_store() {
    let cell = SnapshotCell::new(1);
    assert_eq!(cell.read(|value| *value), 1);
    assert_eq!(cell.read(|value| *value), 1);
    cell.store(2);
    assert_eq!(cell.read(|value| *value), 2);
    assert_eq!((*cell.load(), cell.read(|value| *value)), (2, 2));
}

/// More cells than cache entries, read in turn on one thread and replaced between rounds:
/// every read gets its own cell's current value.
#[test]
fn cells_read_in_turn_beyond_the_cache_never_mix() {
    let cells: Vec<_> = (0..=2 * CACHE_ENTRIES)
        .map(|id| SnapshotCell::new((id, 0)))
        .collect();
    for round in 0..4 {
        for _ in 0..2 {
            for (id, cell) in cells.iter().enumerate() {
                assert_eq!(cell.read(|value| *value), (id, round));
            }
        }
        for (id, cell) in cells.iter().enumerate().step_by(2) {
            cell.store((id, round + 1));
        }
        for (id, cell) in cells.iter().enumerate().skip(1).step_by(2) {
            cell.store((id, round + 1));
        }
    }
}

#[test]
fn nested_reads_of_the_same_and_other_cells() {
    let (outer, other) = (SnapshotCell::new(1), SnapshotCell::new(10));
    outer.read(|_| ());
    // A hit outside, a hit and a miss inside.
    let read = outer.read(|first| {
        let again = outer.read(|again| *again);
        let missed = other.read(|other| *other);
        let nested = other.read(|other| outer.read(|again| other + again));
        (*first, again, missed, nested)
    });
    assert_eq!(read, (1, 1, 10, 11));
    // A store inside: the outer closure keeps its value, an inner read misses, sees the new
    // one and caches it, so the next inner read hits.
    let read = outer.read(|first| {
        outer.store(2);
        (
            *first,
            outer.read(|again| *again),
            outer.read(|again| *again),
        )
    });
    assert_eq!(read, (1, 2, 2));
    assert_eq!(
        (outer.read(|value| *value), other.read(|value| *value)),
        (2, 10)
    );
}

fn refills() -> usize {
    REFILLS.with(std::cell::Cell::get)
}

/// A read inside the closure of another fills the cache: after a store, the first inner read
/// loads the shard and the next ones hit.
#[test]
fn a_nested_read_fills_the_cache() {
    thread::spawn(|| {
        let (outer, other) = (SnapshotCell::new(1), SnapshotCell::new(10));
        outer.read(|_| ());
        let before = refills();
        let read = outer.read(|first| {
            outer.store(2);
            let missed = outer.read(|again| *again);
            let filled = refills();
            let hit = outer.read(|again| *again);
            (*first, missed, hit, filled, refills())
        });
        assert_eq!(read, (1, 2, 2, before + 1, before + 1));
        // Another cell's value, cached by a nested read.
        outer.read(|_| other.read(|_| ()));
        let before = refills();
        assert_eq!(outer.read(|_| other.read(|value| *value)), 10);
        assert_eq!(refills(), before, "both reads hit");
    })
    .join()
    .unwrap();
}

/// Sets its flag when it drops.
struct DropMarker(Arc<AtomicBool>);

impl Drop for DropMarker {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// Reads of more cells than the cache holds inside a closure evict the outer read's entry;
/// the outer closure's value stays whole and drops only once that closure returns.
#[test]
fn inner_reads_evict_the_entry_of_an_outer_read() {
    thread::spawn(|| {
        let dropped = Arc::new(AtomicBool::new(false));
        let cell = SnapshotCell::new(DropMarker(Arc::clone(&dropped)));
        let others: Vec<_> = (0..=CACHE_ENTRIES)
            .map(SnapshotCell::<usize>::new)
            .collect();
        cell.read(|_| ());
        cell.read(|value| {
            cell.store(DropMarker(Arc::new(AtomicBool::new(false))));
            for (other, expected) in others.iter().zip(0..) {
                assert_eq!(other.read(|value| *value), expected);
            }
            assert!(
                Arc::ptr_eq(&value.0, &dropped),
                "the outer value is unchanged"
            );
            assert!(!dropped.load(Ordering::Relaxed), "the outer value is alive");
        });
        assert!(
            dropped.load(Ordering::Relaxed),
            "dropped once the outer read returned"
        );
    })
    .join()
    .unwrap();
}

/// A value whose drop reads a cell, released by the read that lent it when its closure returns.
#[test]
fn a_value_whose_drop_reads_a_cell_drops_after_a_read() {
    struct ReadOnDrop(Arc<SnapshotCell<u32>>, Arc<Mutex<Option<u32>>>);

    impl Drop for ReadOnDrop {
        fn drop(&mut self) {
            *self.1.lock().unwrap() = Some(self.0.read(|value| *value));
        }
    }

    thread::spawn(|| {
        let (other, read) = (Arc::new(SnapshotCell::new(7)), Arc::new(Mutex::new(None)));
        let cell = SnapshotCell::new(ReadOnDrop(Arc::clone(&other), Arc::clone(&read)));
        let (spare_other, spare_read) = (Arc::clone(&other), Arc::new(Mutex::new(None)));
        cell.read(|_| ());
        cell.read(|_| {
            cell.store(ReadOnDrop(spare_other, spare_read));
            // Replaces the cache entry: only this closure's read still holds the old value.
            cell.read(|_| ());
            let dropped = *read.lock().unwrap();
            assert_eq!(dropped, None);
        });
        let dropped = *read.lock().unwrap();
        assert_eq!(dropped, Some(7));
        assert_eq!(other.read(|value| *value), 7);
    })
    .join()
    .unwrap();
}

#[test]
fn store_inside_a_read() {
    let cell = SnapshotCell::new(1);
    for expected in 1..4 {
        cell.read(|value| {
            assert_eq!(*value, expected);
            cell.store(value + 1);
            assert_eq!(*value, expected);
        });
    }
    assert_eq!(cell.read(|value| *value), 4);
}

#[test]
fn reads_on_more_threads_than_shards_see_a_store() {
    let readers = 2 * SHARDS + 1;
    let cell = Arc::new(SnapshotCell::new(0));
    let (read, stored) = (
        Arc::new(Barrier::new(readers + 1)),
        Arc::new(Barrier::new(readers + 1)),
    );
    let threads: Vec<_> = (0..readers)
        .map(|_| {
            let (cell, read, stored) = (Arc::clone(&cell), Arc::clone(&read), Arc::clone(&stored));
            thread::spawn(move || {
                let before = cell.read(|value| *value);
                read.wait();
                stored.wait();
                (before, cell.read(|value| *value))
            })
        })
        .collect();
    read.wait();
    cell.store(1);
    stored.wait();
    for thread in threads {
        assert_eq!(thread.join().unwrap(), (0, 1));
    }
}

/// Like `cells_replaced_under_load_never_mix_or_go_back`, with readers on more threads than
/// shards that read every cell in turn, mixing `read` and `load`.
#[test]
fn cells_replaced_under_read_never_mix_or_go_back() {
    const CELLS: usize = 4;
    const READERS: usize = SHARDS;
    const MAX_STORES: u64 = 2_000_000;
    let deadline = Instant::now() + Duration::from_secs(2);

    let cells: Arc<Vec<_>> = Arc::new(
        (0..CELLS)
            .map(|id| SnapshotCell::new((id, 0_u64)))
            .collect(),
    );
    let done = Arc::new(AtomicBool::new(false));
    let readers: Vec<_> = (0..READERS)
        .map(|_| {
            let (cells, done) = (Arc::clone(&cells), Arc::clone(&done));
            thread::spawn(move || {
                let mut last = [0_u64; CELLS];
                let mut count = 0_u64;
                while !done.load(Ordering::Relaxed) {
                    for (id, cell) in cells.iter().enumerate() {
                        let (owner, sequence) = if count.is_multiple_of(3) {
                            *cell.load()
                        } else {
                            cell.read(|value| *value)
                        };
                        assert_eq!(owner, id, "a value of another cell");
                        assert!(
                            sequence >= last[id],
                            "{sequence} went back from {}",
                            last[id]
                        );
                        last[id] = sequence;
                        count += 1;
                    }
                }
            })
        })
        .collect();
    let writers: Vec<_> = (0..CELLS)
        .map(|id| {
            let cells = Arc::clone(&cells);
            thread::spawn(move || {
                let mut sequence = 0;
                while sequence < MAX_STORES && Instant::now() < deadline {
                    sequence += 1;
                    cells[id].store((id, sequence));
                }
            })
        })
        .collect();
    assert!(readers.len() + writers.len() > SHARDS);
    for writer in writers {
        writer.join().unwrap();
    }
    done.store(true, Ordering::Relaxed);
    for reader in readers {
        reader.join().unwrap();
    }
    for (id, cell) in cells.iter().enumerate() {
        let (owner, sequence) = cell.read(|value| *value);
        assert_eq!((owner, *cell.load()), (id, (id, sequence)));
        assert!(sequence > 0);
    }
}

/// Several threads store into one cell while others read it: no read waits forever, a reader
/// never sees a writer's values go back, and the final value is the last of some writer.
#[test]
fn concurrent_stores_with_readers() {
    const WRITERS: usize = 4;
    const READERS: usize = 4;
    const MAX_STORES: u64 = 500_000;
    let deadline = Instant::now() + Duration::from_secs(1);

    let cell = Arc::new(SnapshotCell::new((0_usize, 0_u64)));
    let done = Arc::new(AtomicBool::new(false));
    let readers: Vec<_> = (0..READERS)
        .map(|_| {
            let (cell, done) = (Arc::clone(&cell), Arc::clone(&done));
            thread::spawn(move || {
                let mut last = [0_u64; WRITERS];
                let mut count = 0_u64;
                while !done.load(Ordering::Relaxed) {
                    let (writer, sequence) = if count.is_multiple_of(4) {
                        *cell.load()
                    } else {
                        cell.read(|value| *value)
                    };
                    assert!(sequence >= last[writer], "{sequence} went back");
                    last[writer] = sequence;
                    count += 1;
                }
            })
        })
        .collect();
    let writers: Vec<_> = (0..WRITERS)
        .map(|writer| {
            let cell = Arc::clone(&cell);
            thread::spawn(move || {
                let mut sequence = 0;
                while sequence < MAX_STORES && Instant::now() < deadline {
                    sequence += 1;
                    cell.store((writer, sequence));
                }
                sequence
            })
        })
        .collect();
    let mut last = Vec::new();
    for writer in writers {
        last.push(writer.join().unwrap());
    }
    done.store(true, Ordering::Relaxed);
    for reader in readers {
        reader.join().unwrap();
    }
    let (writer, sequence) = cell.read(|value| *value);
    assert_eq!(sequence, last[writer]);
    assert_eq!(*cell.load(), (writer, sequence));
}

/// A replaced value stays in the cache of a thread that read it until the thread reads the
/// cell again or evicts it.
#[test]
fn the_cache_retains_a_replaced_value_until_evicted() {
    thread::spawn(|| {
        let value = Arc::new(1);
        let (old, cell) = (Arc::downgrade(&value), SnapshotCell::new(value));
        cell.read(|_| ());
        cell.store(2);
        assert!(old.upgrade().is_some(), "cached");
        assert_eq!(cell.read(|value| *value), 2);
        assert!(old.upgrade().is_none(), "the read replaced it");

        let value = Arc::new(3);
        let old = Arc::downgrade(&value);
        cell.store(value);
        cell.read(|_| ());
        cell.store(4);
        let others: Vec<_> = (0..CACHE_ENTRIES).map(SnapshotCell::<usize>::new).collect();
        for (other, expected) in others.iter().zip(0..) {
            assert!(old.upgrade().is_some(), "cached");
            assert_eq!(other.read(|value| *value), expected);
        }
        assert!(old.upgrade().is_none(), "evicted");
    })
    .join()
    .unwrap();
}

/// A thread-local whose drop reads a cell, initialized before the cache so that it drops
/// after it on Linux: the read loads the shard.
#[test]
fn a_read_while_the_thread_exits() {
    struct ReadOnDrop(Arc<SnapshotCell<u32>>, Arc<Mutex<Option<u32>>>);

    impl Drop for ReadOnDrop {
        fn drop(&mut self) {
            *self.1.lock().unwrap() = Some(self.0.read(|value| *value));
        }
    }

    thread_local! {
        static PROBE: RefCell<Option<ReadOnDrop>> = const { RefCell::new(None) };
    }

    let cell = Arc::new(SnapshotCell::new(1));
    let read = Arc::new(Mutex::new(None));
    {
        let (cell, read) = (Arc::clone(&cell), Arc::clone(&read));
        thread::spawn(move || {
            PROBE.with(|probe| *probe.borrow_mut() = Some(ReadOnDrop(Arc::clone(&cell), read)));
            assert_eq!(cell.read(|value| *value), 1);
            cell.store(2);
        })
        .join()
        .unwrap();
    }
    assert_eq!(*read.lock().unwrap(), Some(2));
}
