//! Opt-in decision events of a [`FlowGate`]: a bounded, rate-limited, lossy
//! channel enabled with [`FlowGate::enable_events`].

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use nsplane_packet::PeerId;

use super::addr::GateAddr;
use super::{FlowGate, GateDecision, GateReason};
use crate::rules::RuleId;

/// Bounds of the decision event channel enabled by
/// [`FlowGate::enable_events`]. Build it with `..Default::default()` so
/// fields added later keep the construction compiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateEventsConfig {
    /// Events buffered for the receiver; an event finding the buffer full is
    /// dropped. With 0 an event is delivered only to a receiver blocked in
    /// [`GateEvents::recv`] or [`GateEvents::recv_timeout`] at that moment.
    pub capacity: usize,
    /// Sustained emission rate of the token bucket, in events per second
    /// of the gate clock. With 0 the bucket never refills.
    pub rate: u32,
    /// Size of the token bucket: events emitted back to back before the
    /// rate applies. The bucket starts full. With 0 nothing is emitted.
    pub burst: u32,
}

impl Default for GateEventsConfig {
    /// 1024 buffered events, 1000 events per second, a burst of 1000.
    fn default() -> Self {
        Self {
            capacity: 1024,
            rate: 1000,
            burst: 1000,
        }
    }
}

/// One new-flow decision of a [`FlowGate`].
///
/// Emitted for a [`GateReason::Granted`] allow and for every denial, enforced
/// or observed, whatever its reason. Packets of existing flows
/// ([`GateReason::ValidState`]) and [`GateDecision::Pass`] never emit.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct GateEvent {
    /// When the gate decided, read from the gate clock.
    pub at: Instant,
    /// The peer the packet was received from or is sent to.
    pub peer: PeerId,
    /// The IP protocol (for IPv6, behind the extension headers); for a
    /// packet that cannot be parsed, the fixed header's protocol or next
    /// header field.
    pub protocol: u8,
    /// The packet's source address and port.
    pub src: SocketAddr,
    /// The packet's destination address and port.
    pub dst: SocketAddr,
    /// Whether the packet is (or under enforcement would be) allowed.
    pub allow: bool,
    /// Whether the decision is enforced ([`GateDecision::Enforce`]) rather
    /// than observed ([`GateDecision::Observe`]).
    pub enforced: bool,
    /// Why.
    pub reason: GateReason,
    /// The admitting grant ([`GateReason::Granted`]) or the first matching
    /// suspended grant ([`GateReason::Suspended`]).
    pub rule: Option<RuleId>,
}

/// The receiving side of the decision events of a [`FlowGate`], returned by
/// [`FlowGate::enable_events`].
///
/// Disconnected once the gate is dropped, its events are disabled or
/// replaced by another [`FlowGate::enable_events`]; the events already
/// buffered are still received. Dropping it does not stop emission: the
/// gate keeps counting each event as dropped until
/// [`FlowGate::disable_events`].
#[derive(Debug)]
pub struct GateEvents {
    receiver: Receiver<GateEvent>,
}

impl GateEvents {
    /// The next buffered event without waiting; `None` when none is
    /// buffered.
    #[must_use]
    pub fn try_recv(&self) -> Option<GateEvent> {
        self.receiver.try_recv().ok()
    }

    /// The next event, waiting for one; `None` once disconnected and
    /// drained.
    #[must_use]
    pub fn recv(&self) -> Option<GateEvent> {
        self.receiver.recv().ok()
    }

    /// The next event, waiting at most `timeout`; `None` on timeout or once
    /// disconnected and drained.
    #[must_use]
    pub fn recv_timeout(&self, timeout: Duration) -> Option<GateEvent> {
        self.receiver.recv_timeout(timeout).ok()
    }

    /// Every buffered event, without waiting.
    pub fn drain(&self) -> impl Iterator<Item = GateEvent> + '_ {
        self.receiver.try_iter()
    }
}

/// A token bucket in nanotokens (one token is `NANOS` units), refilled by
/// the elapsed gate time.
#[derive(Debug)]
struct Bucket {
    tokens: u128,
    refilled_at: Instant,
}

const NANOS: u128 = 1_000_000_000;

/// The sending side installed in a [`FlowGate`].
#[derive(Debug)]
pub(super) struct EventSink {
    sender: SyncSender<GateEvent>,
    rate: u128,
    capacity: u128,
    bucket: Mutex<Bucket>,
}

impl EventSink {
    pub(super) fn new(config: GateEventsConfig, now: Instant) -> (Self, GateEvents) {
        let (sender, receiver) = sync_channel(config.capacity);
        let capacity = u128::from(config.burst) * NANOS;
        let sink = Self {
            sender,
            rate: u128::from(config.rate),
            capacity,
            bucket: Mutex::new(Bucket {
                tokens: capacity,
                refilled_at: now,
            }),
        };
        (sink, GateEvents { receiver })
    }

    /// Take one token at `now`; `false` when the bucket is empty.
    fn take(&self, now: Instant) -> bool {
        let mut bucket = self.bucket.lock().unwrap_or_else(PoisonError::into_inner);
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
}

/// Emitted and dropped event counts of a [`FlowGate`].
#[derive(Debug, Default)]
pub(super) struct EventCounters {
    pub(super) emitted: AtomicU64,
    pub(super) dropped: AtomicU64,
}

impl FlowGate {
    /// Emit the event of `decision` for `packet` from `peer` if the decision
    /// emits, a token is available and the channel has room; otherwise an
    /// emitting decision is counted as dropped. Never blocks on the channel.
    pub(super) fn emit_event(&self, peer: PeerId, packet: &[u8], decision: &GateDecision) {
        let (allow, enforced, reason, rule) = match decision {
            GateDecision::Pass => return,
            GateDecision::Observe { reason, .. } | GateDecision::Enforce { reason, .. }
                if *reason == GateReason::ValidState =>
            {
                return;
            }
            GateDecision::Observe {
                allow,
                reason,
                rule,
            } => (*allow, false, *reason, rule),
            GateDecision::Enforce {
                allow,
                reason,
                rule,
            } => (*allow, true, *reason, rule),
        };
        self.events.read(|sink| {
            let Some(sink) = sink else {
                return;
            };
            let dropped = || self.event_counters.dropped.fetch_add(1, Ordering::Relaxed);
            let now = (self.clock)();
            if !sink.take(now) {
                dropped();
                return;
            }
            // Every packet the gate decides on has readable addresses.
            let Some((protocol, src, dst)) = five_tuple(packet) else {
                dropped();
                return;
            };
            let event = GateEvent {
                at: now,
                peer,
                protocol,
                src,
                dst,
                allow,
                enforced,
                reason,
                rule: rule.clone(),
            };
            match sink.sender.try_send(event) {
                Ok(()) => {
                    self.event_counters.emitted.fetch_add(1, Ordering::Relaxed);
                }
                Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
                    dropped();
                }
            }
        });
    }
}

/// The protocol, source and destination of an IPv4 or IPv6 packet; ports are
/// 0 when the packet has none (or they cannot be parsed).
fn five_tuple(packet: &[u8]) -> Option<(u8, SocketAddr, SocketAddr)> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => family_five_tuple::<Ipv4Addr>(packet, 9),
        Some(6) => family_five_tuple::<Ipv6Addr>(packet, 6),
        _ => None,
    }
}

/// [`five_tuple`] of the family `A`, whose fixed header carries the protocol
/// at `protocol_offset`.
fn family_five_tuple<A: GateAddr>(
    packet: &[u8],
    protocol_offset: usize,
) -> Option<(u8, SocketAddr, SocketAddr)> {
    let endpoint = |ip: A, port: Option<u16>| SocketAddr::new(ip.ip(), port.unwrap_or(0));
    if let Some(meta) = A::parse(packet) {
        return Some((
            meta.protocol,
            endpoint(meta.source, meta.src_port),
            endpoint(meta.destination, meta.dst_port),
        ));
    }
    let (source, destination) = A::endpoints(packet)?;
    let protocol = packet.get(protocol_offset).copied().unwrap_or(0);
    Some((
        protocol,
        SocketAddr::new(source.ip(), 0),
        SocketAddr::new(destination.ip(), 0),
    ))
}
