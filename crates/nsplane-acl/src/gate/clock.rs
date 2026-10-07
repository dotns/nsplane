//! The default clock of the gate: the kernel's coarse monotonic clock on Linux
//! and Android (one scheduler tick, 1 to 4 ms, of resolution at a fraction of
//! the cost of [`Instant::now`]), which the second-scale flow and fragment
//! timeouts do not notice; [`Instant::now`] elsewhere.

use std::time::Instant;

/// The coarse clock as an [`Instant`]: the time of the first read plus the
/// coarse time since, so it advances with the monotonic clock.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(super) fn coarse() -> impl Fn() -> Instant + Send + Sync + 'static {
    use std::time::Duration;

    use nix::time::{ClockId, clock_gettime};

    let read = || {
        clock_gettime(ClockId::CLOCK_MONOTONIC_COARSE)
            .ok()
            .map(Duration::from)
    };
    let (start, coarse_start) = (Instant::now(), read());
    move || {
        // Without the coarse clock (never on these targets) the precise one.
        coarse_start
            .zip(read())
            .and_then(|(coarse_start, now)| start.checked_add(now.saturating_sub(coarse_start)))
            .unwrap_or_else(Instant::now)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub(super) fn coarse() -> impl Fn() -> Instant + Send + Sync + 'static {
    Instant::now
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn coarse_clock_follows_the_monotonic_clock() {
        let clock = coarse();
        let (coarse_start, start) = (clock(), Instant::now());
        std::thread::sleep(Duration::from_millis(30));
        let (coarse_end, end) = (clock(), Instant::now());
        let (coarse, precise) = (coarse_end - coarse_start, end - start);
        // Within a few ticks of the precise clock (ticks are at most 4 ms).
        let slack = Duration::from_millis(12);
        assert!(coarse + slack >= precise, "{coarse:?} against {precise:?}");
        assert!(coarse <= precise + slack, "{coarse:?} against {precise:?}");
        assert!(clock() >= coarse_end);
    }
}
