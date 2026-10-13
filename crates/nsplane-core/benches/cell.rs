//! `SnapshotCell::load` (a load and its drop) and `SnapshotCell::read` (a closure read of an
//! unchanged value), on one thread and on 8 threads using the same cell concurrently; the
//! 8-thread cases report the time of one load or read on each thread. `read_4_cells_interleaved`
//! reads four cells in turn on one thread and reports the time of one read.

use std::hint::black_box;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use criterion::Criterion;
use nsplane_core::cell::SnapshotCell;

/// Threads of the concurrent cases.
const THREADS: usize = 8;

/// The time `threads` threads take to each run `op` `iters` times on one cell.
fn on_threads(
    cell: &Arc<SnapshotCell<u64>>,
    threads: usize,
    iters: u64,
    op: fn(&SnapshotCell<u64>),
) -> Duration {
    let start = Arc::new(Barrier::new(threads + 1));
    let workers: Vec<_> = (0..threads)
        .map(|_| {
            let (cell, start) = (Arc::clone(cell), Arc::clone(&start));
            thread::spawn(move || {
                start.wait();
                for _ in 0..iters {
                    op(&cell);
                }
            })
        })
        .collect();
    start.wait();
    let begin = Instant::now();
    for worker in workers {
        let _ = worker.join();
    }
    begin.elapsed()
}

fn load(cell: &SnapshotCell<u64>) {
    black_box(cell.load());
}

fn read(cell: &SnapshotCell<u64>) {
    black_box(cell.read(|value| *value));
}

fn cell(c: &mut Criterion) {
    let cell = Arc::new(SnapshotCell::new(7_u64));
    let cells: Vec<_> = (0..4_u64).map(SnapshotCell::<u64>::new).collect();
    let mut group = c.benchmark_group("cell");
    group.bench_function("load_1_thread", |b| b.iter(|| load(&cell)));
    group.bench_function("load_8_threads", |b| {
        b.iter_custom(|iters| on_threads(&cell, THREADS, iters, load));
    });
    group.bench_function("read_1_thread", |b| b.iter(|| read(&cell)));
    group.bench_function("read_8_threads", |b| {
        b.iter_custom(|iters| on_threads(&cell, THREADS, iters, read));
    });
    group.bench_function("read_4_cells_interleaved", |b| {
        b.iter_custom(|iters| {
            let begin = Instant::now();
            for cell in cells.iter().cycle().take(iters as usize) {
                read(cell);
            }
            begin.elapsed()
        });
    });
    group.finish();
}

criterion::criterion_group!(benches, cell);
criterion::criterion_main!(benches);
