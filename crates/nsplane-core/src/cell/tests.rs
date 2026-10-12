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
