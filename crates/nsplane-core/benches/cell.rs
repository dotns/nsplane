//! `SnapshotCell::load` (a load and its drop), on one thread and on 8 threads loading the
//! same cell concurrently; the 8-thread case reports the time of one load on each thread.

use std::hint::black_box;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use criterion::Criterion;
use nsplane_core::cell::SnapshotCell;

/// Threads of the concurrent case.
const THREADS: usize = 8;

/// The time `threads` threads take to each load and drop `iters` values of one cell.
fn load(cell: &Arc<SnapshotCell<u64>>, threads: usize, iters: u64) -> Duration {
    let start = Arc::new(Barrier::new(threads + 1));
    let workers: Vec<_> = (0..threads)
        .map(|_| {
            let (cell, start) = (Arc::clone(cell), Arc::clone(&start));
            thread::spawn(move || {
                start.wait();
                for _ in 0..iters {
                    black_box(cell.load());
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

fn cell(c: &mut Criterion) {
    let cell = Arc::new(SnapshotCell::new(7_u64));
    let mut group = c.benchmark_group("cell");
    group.bench_function("load_1_thread", |b| b.iter(|| black_box(cell.load())));
    group.bench_function("load_8_threads", |b| {
        b.iter_custom(|iters| load(&cell, THREADS, iters));
    });
    group.finish();
}

criterion::criterion_group!(benches, cell);
criterion::criterion_main!(benches);
