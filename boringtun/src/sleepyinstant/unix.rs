use std::time::Duration;

use nix::sys::time::TimeSpec;
use nix::time::{ClockId, clock_gettime};

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "freebsd",
    target_os = "netbsd"
))]
const CLOCK_ID: ClockId = ClockId::CLOCK_MONOTONIC;
#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "freebsd",
    target_os = "netbsd"
)))]
const CLOCK_ID: ClockId = ClockId::CLOCK_BOOTTIME;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Instant {
    t: TimeSpec,
}

impl Instant {
    pub(crate) fn now() -> Self {
        // std::time::Instant panics as well: the clock is always available on these targets.
        #[allow(
            clippy::expect_used,
            reason = "INVARIANT: the monotonic clock always exists"
        )]
        let t = clock_gettime(CLOCK_ID).expect("INVARIANT: the monotonic clock always exists");
        Self { t }
    }

    fn checked_duration_since(&self, earlier: Self) -> Option<Duration> {
        const NANOSECOND: nix::libc::c_long = 1_000_000_000;
        let (tv_sec, tv_nsec) = if self.t.tv_nsec() < earlier.t.tv_nsec() {
            (
                self.t.tv_sec() - earlier.t.tv_sec() - 1,
                self.t.tv_nsec() - earlier.t.tv_nsec() + NANOSECOND,
            )
        } else {
            (
                self.t.tv_sec() - earlier.t.tv_sec(),
                self.t.tv_nsec() - earlier.t.tv_nsec(),
            )
        };

        if tv_sec < 0 {
            None
        } else {
            Some(Duration::new(
                u64::try_from(tv_sec).ok()?,
                u32::try_from(tv_nsec).ok()?,
            ))
        }
    }

    pub(crate) fn duration_since(&self, earlier: Self) -> Duration {
        self.checked_duration_since(earlier)
            .unwrap_or(Duration::ZERO)
    }
}
