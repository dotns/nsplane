//! A limit on how often a call site logs, for the logs a remote peer can cause per packet.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// The least time between two logs of one call site, in milliseconds.
const INTERVAL: u64 = 1000;

/// Lets one log through per [`INTERVAL`] and counts the others. One per call site, in a
/// `static`, so every stack of the process shares it.
#[derive(Debug)]
pub(crate) struct LogLimit {
    /// The time the next log is let through at, in milliseconds since the first use of
    /// any limit.
    next: AtomicU64,
    /// The logs held back since the last one let through.
    suppressed: AtomicU64,
}

impl LogLimit {
    pub(crate) const fn new() -> Self {
        Self {
            next: AtomicU64::new(0),
            suppressed: AtomicU64::new(0),
        }
    }

    /// `Some` when the caller may log now, with the number of logs held back since the
    /// last one; `None` counts this one as held back.
    pub(crate) fn admit(&self) -> Option<u64> {
        static START: OnceLock<Instant> = OnceLock::new();
        let elapsed = START.get_or_init(Instant::now).elapsed().as_millis();
        self.admit_at(u64::try_from(elapsed).unwrap_or(u64::MAX))
    }

    /// [`admit`](Self::admit) at `now`, in milliseconds.
    fn admit_at(&self, now: u64) -> Option<u64> {
        let next = self.next.load(Ordering::Relaxed);
        let admitted = now >= next
            && self
                .next
                .compare_exchange(
                    next,
                    now.saturating_add(INTERVAL),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok();
        if admitted {
            Some(self.suppressed.swap(0, Ordering::Relaxed))
        } else {
            self.suppressed.fetch_add(1, Ordering::Relaxed);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_log_per_interval_carries_the_suppressed_count() {
        let limit = LogLimit::new();
        assert_eq!(limit.admit_at(0), Some(0));
        assert_eq!(limit.admit_at(1), None);
        assert_eq!(limit.admit_at(INTERVAL - 1), None);
        assert_eq!(limit.admit_at(INTERVAL), Some(2));
        assert_eq!(limit.admit_at(INTERVAL + 1), None);
        assert_eq!(limit.admit_at(3 * INTERVAL), Some(1));
        assert_eq!(limit.admit_at(4 * INTERVAL), Some(0));
    }
}
