//! Opt-in admission events of a transparent stack: a bounded, rate-limited, lossy
//! channel enabled with [`TransparentConfig::events`](crate::TransparentConfig::events).

use std::net::SocketAddr;
use std::time::Instant;

use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

use crate::stats::{self, Counters};

/// Bounds of the admission event channel of
/// [`TransparentConfig::events`](crate::TransparentConfig::events).
///
/// Fields may be added in any release. Start from [`Default::default`] and assign the
/// fields to change:
///
/// ```
/// use nsplane_netstack::FlowEventsConfig;
///
/// let mut events = FlowEventsConfig::default();
/// events.rate = 100;
/// assert_eq!(events.capacity, 1024);
/// ```
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowEventsConfig {
    /// Events buffered for the receiver; an event finding the buffer full is dropped. A
    /// capacity of 0 is taken as 1.
    pub capacity: usize,
    /// Sustained emission rate of the token bucket, in events per second. With 0 the
    /// bucket never refills.
    pub rate: u32,
    /// Size of the token bucket: events emitted back to back before the rate applies.
    /// The bucket starts full. With 0 nothing is emitted.
    pub burst: u32,
}

impl Default for FlowEventsConfig {
    /// 1024 buffered events, 1000 events per second, a burst of 1000.
    fn default() -> Self {
        Self {
            capacity: 1024,
            rate: 1000,
            burst: 1000,
        }
    }
}

/// Why a transparent stack admitted or rejected a connection, flow or packet.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowEventReason {
    /// Admitted: on arrival under [`Admission::Immediate`](crate::Admission::Immediate),
    /// or accepted by the application under [`Admission::Decide`](crate::Admission::Decide).
    /// Counted in [`accepted`](crate::NetStackStats::accepted).
    Admitted,
    /// Rejected by the application, or its [`PendingFlow`](crate::PendingFlow) was dropped
    /// or could not be offered; see
    /// [`rejected_hook`](crate::NetStackStats::rejected_hook).
    Hook,
    /// No decision came within the [`Admission::Decide`](crate::Admission::Decide) timeout;
    /// see [`rejected_timeout`](crate::NetStackStats::rejected_timeout).
    Timeout,
    /// The pending table was full; see
    /// [`rejected_table_full`](crate::NetStackStats::rejected_table_full).
    TableFull,
    /// The stack held
    /// [`max_connections`](crate::TransparentConfig::max_connections) TCP connections;
    /// see [`rejected_connection_limit`](crate::NetStackStats::rejected_connection_limit).
    ConnectionLimit,
    /// The destination is outside
    /// [`prefixes`](crate::TransparentConfig::prefixes) and not one of the stack's
    /// addresses; see [`rejected_prefix`](crate::NetStackStats::rejected_prefix).
    Prefix,
}

/// One admission decision of a transparent stack.
///
/// Emitted for each new TCP connection (bare SYN) and UDP flow (first datagram) the stack
/// admits or rejects, and for each packet dropped for its destination prefix: one event
/// per increment of [`accepted`](crate::NetStackStats::accepted) or of a `rejected_`
/// counter of [`NetStackStats`](crate::NetStackStats).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowEvent {
    /// When the stack decided, read from the tokio clock.
    pub at: Instant,
    /// The IP protocol of the packet decided on (IPv4 protocol, IPv6 next header).
    pub protocol: u8,
    /// The packet's source address and port: the peer. The port is 0 for a packet
    /// without readable ports.
    pub src: SocketAddr,
    /// The packet's destination address and port: the original destination. The port is
    /// 0 for a packet without readable ports.
    pub dst: SocketAddr,
    /// Whether the connection, flow or packet was admitted.
    pub allow: bool,
    /// Why.
    pub reason: FlowEventReason,
}

/// A token bucket in nanotokens (one token is `NANOS` units), refilled by the elapsed
/// time.
#[derive(Debug)]
struct Bucket {
    tokens: u128,
    refilled_at: tokio::time::Instant,
}

const NANOS: u128 = 1_000_000_000;

/// The sending side of the admission events, owned by the driver.
#[derive(Debug)]
pub(crate) struct EventSink {
    sender: mpsc::Sender<FlowEvent>,
    rate: u128,
    capacity: u128,
    bucket: Bucket,
}

impl EventSink {
    /// A sink bounded by `config` with a full bucket at `now`, and its receiver.
    pub(crate) fn new(
        config: FlowEventsConfig,
        now: tokio::time::Instant,
    ) -> (Self, mpsc::Receiver<FlowEvent>) {
        let (sender, receiver) = mpsc::channel(config.capacity.max(1));
        let capacity = u128::from(config.burst) * NANOS;
        let sink = Self {
            sender,
            rate: u128::from(config.rate),
            capacity,
            bucket: Bucket {
                tokens: capacity,
                refilled_at: now,
            },
        };
        (sink, receiver)
    }

    /// Take one token at `now`; `false` when the bucket is empty.
    fn take(&mut self, now: tokio::time::Instant) -> bool {
        let bucket = &mut self.bucket;
        let elapsed = now.saturating_duration_since(bucket.refilled_at);
        bucket.refilled_at = bucket.refilled_at.max(now);
        bucket.tokens = bucket
            .tokens
            .saturating_add(elapsed.as_nanos().saturating_mul(self.rate))
            .min(self.capacity);
        if bucket.tokens < NANOS {
            return false;
        }
        bucket.tokens -= NANOS;
        true
    }

    /// Emits the event of a decision if a token is available and the channel has room;
    /// otherwise counts it as dropped. Never waits.
    pub(crate) fn emit(
        &mut self,
        counters: &Counters,
        protocol: u8,
        src: SocketAddr,
        dst: SocketAddr,
        reason: FlowEventReason,
    ) {
        let now = tokio::time::Instant::now();
        if !self.take(now) {
            return stats::add(&counters.events_dropped, 1);
        }
        let event = FlowEvent {
            at: now.into_std(),
            protocol,
            src,
            dst,
            allow: reason == FlowEventReason::Admitted,
            reason,
        };
        match self.sender.try_send(event) {
            Ok(()) => stats::add(&counters.events_emitted, 1),
            Err(TrySendError::Full(_) | TrySendError::Closed(_)) => {
                stats::add(&counters.events_dropped, 1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn bucket_refills_with_elapsed_time() {
        let start = tokio::time::Instant::now();
        let config = FlowEventsConfig {
            rate: 10,
            burst: 2,
            ..Default::default()
        };
        let (mut sink, _receiver) = EventSink::new(config, start);
        assert!(sink.take(start));
        assert!(sink.take(start));
        assert!(!sink.take(start));
        // 10 per second: one token per 100 ms, capped at the burst.
        assert!(!sink.take(start + Duration::from_millis(99)));
        assert!(sink.take(start + Duration::from_millis(100)));
        assert!(!sink.take(start + Duration::from_millis(100)));
        let later = start + Duration::from_secs(10);
        assert!(sink.take(later));
        assert!(sink.take(later));
        assert!(!sink.take(later));
    }

    #[test]
    fn zero_rate_never_refills_and_zero_burst_emits_nothing() {
        let start = tokio::time::Instant::now();
        let (mut sink, _receiver) = EventSink::new(
            FlowEventsConfig {
                rate: 0,
                burst: 1,
                ..Default::default()
            },
            start,
        );
        assert!(sink.take(start));
        assert!(!sink.take(start + Duration::from_secs(3600)));
        let (mut sink, _receiver) = EventSink::new(
            FlowEventsConfig {
                burst: 0,
                ..Default::default()
            },
            start,
        );
        assert!(!sink.take(start + Duration::from_secs(1)));
    }
}
