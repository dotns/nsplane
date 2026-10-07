//! Bounded connection tracking table (`Conntrack`) for the service-publishing NAT.
//!
//! A [`Conntrack`] remembers translated flows: TCP and UDP five-tuples and
//! ICMP / `ICMPv6` echo flows (keyed by their identifier). Every [`Flow`]
//! stores the tuple of its first packet as the peer sent it (`original`) and
//! the tuple after translation (`translated`); both directions are indexed, so
//! [`Conntrack::lookup`] finds a flow from a packet in the original direction
//! (its tuple equals `original`) and from a reply (its tuple equals the
//! reverse of `translated`).
//!
//! - **Idle timeouts** per protocol ([`ConntrackConfig`]): TCP established and
//!   transitory (handshake, closing, reset; see [`TcpState`]), UDP and ICMP.
//!   Every hit refreshes a flow.
//! - **Bounded**: at most [`ConntrackConfig::max_entries`] flows. Inserting
//!   into a full table removes the least recently seen flow, counted as
//!   expired when its timeout had passed and as evicted otherwise.
//! - **No background task**: the table is used from synchronous packet
//!   filters, which never do I/O. An expired flow is removed when a lookup
//!   finds it, and every insert sweeps a few slots of the table for expired
//!   flows (amortized cleanup).
//! - **Injectable clock** ([`Conntrack::with_clock`]) for deterministic tests;
//!   the default is [`Instant::now`].
//! - **Removal hook** ([`Conntrack::with_removal_hook`]): an optional callback
//!   for every flow that leaves the table (expired, evicted or removed), so
//!   per-flow resources such as a reserved port can be released.
//!
//! All methods take `&self`; the table sits behind one mutex, so a
//! `Conntrack` can be shared by the inbound and outbound paths of a filter.

mod table;
#[cfg(test)]
mod tests;

use std::fmt;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use nsplane_packet::{FiveTuple, PeerId, protocol};
use thiserror::Error;

use self::table::{Entry, Table};

/// Flows examined for expiry by every [`Conntrack::insert`].
const SWEEP_BATCH: usize = 8;

/// TCP flag bits as found in byte 13 of the TCP header.
mod tcp_flags {
    pub(super) const FIN: u8 = 0x01;
    pub(super) const SYN: u8 = 0x02;
    pub(super) const RST: u8 = 0x04;
    pub(super) const ACK: u8 = 0x10;
}

/// Settings of a [`Conntrack`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConntrackConfig {
    /// Maximum number of flows. When full, an insert removes the least
    /// recently seen flow; `0` refuses every insert with
    /// [`ConntrackError::Full`]. Default 65 536.
    pub max_entries: usize,
    /// Idle timeout of an [`Established`](TcpState::Established) TCP flow.
    /// Default 300 s (two kernel keepalive cycles; quiet flows are refreshed
    /// by every packet).
    pub tcp_established_timeout: Duration,
    /// Idle timeout of a TCP flow in any other [`TcpState`] (handshake,
    /// closing, reset). Default 30 s.
    pub tcp_transitory_timeout: Duration,
    /// Idle timeout of a UDP flow. Default 30 s: UDP has no FIN, so flows
    /// rely on an aggressive timeout refreshed by every packet.
    pub udp_timeout: Duration,
    /// Idle timeout of an ICMP / `ICMPv6` echo flow. Default 30 s.
    pub icmp_timeout: Duration,
}

impl Default for ConntrackConfig {
    fn default() -> Self {
        Self {
            max_entries: 65_536,
            tcp_established_timeout: Duration::from_secs(300),
            tcp_transitory_timeout: Duration::from_secs(30),
            udp_timeout: Duration::from_secs(30),
            icmp_timeout: Duration::from_secs(30),
        }
    }
}

/// Counters of a [`Conntrack`], in flows unless stated otherwise.
///
/// Every inserted flow is eventually counted under exactly one of `expired`,
/// `evicted` and `removed`, or is still one of the `entries`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConntrackStats {
    /// Flows in the table now.
    pub entries: usize,
    /// Flows inserted.
    pub inserted: u64,
    /// Flows removed because their idle timeout passed.
    pub expired: u64,
    /// Flows removed before their timeout to make room for a new one.
    pub evicted: u64,
    /// Flows removed by [`Conntrack::retain`] and [`Conntrack::remove`].
    pub removed: u64,
    /// Lookups that found a live flow, in lookups.
    pub hits: u64,
    /// Lookups that found no flow or an expired one, in lookups.
    pub misses: u64,
}

/// The state of a tracked TCP flow, as far as it affects the idle timeout.
///
/// A flow starts in [`SynSent`](Self::SynSent) whatever its first packet is,
/// so a flow picked up in the middle of a connection becomes established only
/// once a reply is seen. Transitions on a packet, in this order:
/// RST -> [`Closed`](Self::Closed); FIN -> [`Closing`](Self::Closing) (unless
/// closed); a reply while `SynSent` -> [`Established`](Self::Established); a
/// SYN without ACK in the original direction while closing or closed (the
/// tuple is reused for a new connection) -> `SynSent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TcpState {
    /// No reply seen yet.
    SynSent,
    /// Both directions have been seen.
    Established,
    /// A FIN has been seen in either direction.
    Closing,
    /// A RST has been seen.
    Closed,
}

impl TcpState {
    /// The state after a packet with TCP `flags` going `direction`.
    const fn next(self, direction: FlowDirection, flags: u8) -> Self {
        if flags & tcp_flags::RST != 0 {
            return Self::Closed;
        }
        if flags & tcp_flags::FIN != 0 {
            return match self {
                Self::Closed => Self::Closed,
                _ => Self::Closing,
            };
        }
        let new_syn = flags & (tcp_flags::SYN | tcp_flags::ACK) == tcp_flags::SYN;
        match (self, direction) {
            (Self::SynSent, FlowDirection::Reply) => Self::Established,
            (Self::Closing | Self::Closed, FlowDirection::Original) if new_syn => Self::SynSent,
            (state, _) => state,
        }
    }
}

/// Which way a packet goes relative to its [`Flow`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowDirection {
    /// The direction of the flow's first packet: the tuple equals
    /// [`Flow::original`].
    Original,
    /// The reply direction: the tuple equals the reverse of
    /// [`Flow::translated`].
    Reply,
}

/// A tracked flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flow {
    /// The peer the flow belongs to.
    pub peer: PeerId,
    /// The tuple of the flow's first packet before translation.
    pub original: FiveTuple,
    /// The tuple of the flow's first packet after translation.
    pub translated: FiveTuple,
    /// The TCP state; `None` for UDP and ICMP flows.
    pub tcp_state: Option<TcpState>,
}

/// A flow found by [`Conntrack::lookup`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowMatch {
    /// Which way the looked-up packet goes.
    pub direction: FlowDirection,
    /// The flow, after the packet's state update.
    pub flow: Flow,
}

/// Why [`Conntrack::insert`] refused a flow. Nothing changes in the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ConntrackError {
    /// [`ConntrackConfig::max_entries`] is 0.
    #[error("conntrack table full")]
    Full,
    /// Another live flow already has the same reply tuple, so replies could
    /// not be told apart.
    #[error("reply tuple in use by another flow")]
    Conflict,
    /// The protocol is not TCP, UDP, ICMP or `ICMPv6`, or the two tuples
    /// differ in protocol.
    #[error("unsupported protocol")]
    Unsupported,
}

/// The callback of [`Conntrack::with_removal_hook`].
type RemovalHook = Box<dyn Fn(&Flow) + Send + Sync>;

/// A bounded connection tracking table. See the [module docs](self).
pub struct Conntrack {
    config: ConntrackConfig,
    table: Mutex<Table>,
    clock: Box<dyn Fn() -> Instant + Send + Sync>,
    on_remove: Option<RemovalHook>,
}

impl Default for Conntrack {
    fn default() -> Self {
        Self::new(ConntrackConfig::default())
    }
}

impl fmt::Debug for Conntrack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Conntrack")
            .field("config", &self.config)
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

impl Conntrack {
    /// An empty table.
    pub fn new(config: ConntrackConfig) -> Self {
        Self::with_clock(config, Instant::now)
    }

    /// An empty table whose timeouts follow `clock` instead of
    /// [`Instant::now`].
    pub fn with_clock(
        config: ConntrackConfig,
        clock: impl Fn() -> Instant + Send + Sync + 'static,
    ) -> Self {
        Self {
            config,
            table: Mutex::new(Table::new()),
            clock: Box::new(clock),
            on_remove: None,
        }
    }

    /// Calls `hook` with every flow that leaves the table: expired, evicted,
    /// or removed by [`retain`](Self::retain) or [`remove`](Self::remove).
    /// Replaces an earlier hook.
    ///
    /// The hook runs under the table lock, so it must be fast and must not
    /// call back into this `Conntrack` (that would deadlock). Without a hook
    /// a removal costs one `Option` check more.
    #[must_use]
    pub fn with_removal_hook(mut self, hook: impl Fn(&Flow) + Send + Sync + 'static) -> Self {
        self.on_remove = Some(Box::new(hook));
        self
    }

    /// The table's settings.
    pub const fn config(&self) -> ConntrackConfig {
        self.config
    }

    /// A snapshot of the counters.
    pub fn stats(&self) -> ConntrackStats {
        self.lock().stats()
    }

    /// Finds the flow of a packet with `tuple`, in either direction, and
    /// refreshes it.
    ///
    /// `tcp_flags` are the TCP flags of the packet (byte 13 of the TCP
    /// header) and advance the flow's [`TcpState`]; pass `None` for a packet
    /// that relates to the flow without belonging to it (an ICMP error
    /// quoting it) and for other protocols. An expired flow is removed and
    /// not returned.
    pub fn lookup(&self, tuple: &FiveTuple, tcp_flags: Option<u8>) -> Option<FlowMatch> {
        let now = (self.clock)();
        let mut table = self.lock();
        let Some((index, direction)) = table.find(tuple) else {
            table.counters.misses += 1;
            return None;
        };
        if table
            .entry(index)
            .is_some_and(|entry| self.is_expired(entry, now))
        {
            self.remove_at(&mut table, index);
            table.counters.expired += 1;
            table.counters.misses += 1;
            return None;
        }
        let entry = table.entry_mut(index)?;
        if let (Some(state), Some(flags)) = (entry.flow.tcp_state, tcp_flags) {
            entry.flow.tcp_state = Some(state.next(direction, flags));
        }
        entry.last_seen = now;
        let flow = entry.flow;
        table.touch(index);
        table.counters.hits += 1;
        Some(FlowMatch { direction, flow })
    }

    /// Finds the flow of a packet with `tuple`, in either direction, without
    /// touching it: unlike [`lookup`](Self::lookup) it neither refreshes the
    /// flow, advances its [`TcpState`] or changes its place in the eviction
    /// order, nor counts a hit or miss. A flow past its idle timeout is not
    /// returned (and left for the next lookup or sweep to remove).
    pub fn peek(&self, tuple: &FiveTuple) -> Option<FlowMatch> {
        let now = (self.clock)();
        let table = self.lock();
        let (index, direction) = table.find(tuple)?;
        let entry = table
            .entry(index)
            .filter(|entry| !self.is_expired(entry, now))?;
        Some(FlowMatch {
            direction,
            flow: entry.flow,
        })
    }

    /// Inserts the flow of a first packet `original` from `peer` that is
    /// translated to `translated`, and returns it.
    ///
    /// When a live flow with the same original tuple exists, it is refreshed
    /// and returned unchanged instead. `tcp_flags` set the initial
    /// [`TcpState`] of a TCP flow (ignored for other protocols). A full table
    /// first drops the least recently seen flow.
    pub fn insert(
        &self,
        peer: PeerId,
        original: FiveTuple,
        translated: FiveTuple,
        tcp_flags: u8,
    ) -> Result<Flow, ConntrackError> {
        if original.protocol != translated.protocol
            || !matches!(
                original.protocol,
                protocol::TCP | protocol::UDP | protocol::ICMP | protocol::ICMPV6
            )
        {
            return Err(ConntrackError::Unsupported);
        }
        let now = (self.clock)();
        let mut table = self.lock();
        self.sweep(&mut table, now);

        if let Some((index, FlowDirection::Original)) = table.find(&original) {
            if let Some(entry) = table.entry_mut(index)
                && !self.is_expired(entry, now)
            {
                entry.last_seen = now;
                let flow = entry.flow;
                table.touch(index);
                return Ok(flow);
            }
            self.remove_at(&mut table, index);
            table.counters.expired += 1;
        }
        let reply = reverse(&translated);
        if let Some(index) = table.reply_index(&reply) {
            if table
                .entry(index)
                .is_some_and(|entry| !self.is_expired(entry, now))
            {
                return Err(ConntrackError::Conflict);
            }
            self.remove_at(&mut table, index);
            table.counters.expired += 1;
        }

        if self.config.max_entries == 0 {
            return Err(ConntrackError::Full);
        }
        while table.len() >= self.config.max_entries {
            let Some(oldest) = table.oldest() else {
                break;
            };
            let expired = table
                .entry(oldest)
                .is_some_and(|entry| self.is_expired(entry, now));
            self.remove_at(&mut table, oldest);
            if expired {
                table.counters.expired += 1;
            } else {
                table.counters.evicted += 1;
            }
        }

        let tcp_state = (original.protocol == protocol::TCP)
            .then(|| TcpState::SynSent.next(FlowDirection::Original, tcp_flags));
        let flow = Flow {
            peer,
            original,
            translated,
            tcp_state,
        };
        table.insert(
            Entry {
                flow,
                last_seen: now,
            },
            reply,
        );
        table.counters.inserted += 1;
        Ok(flow)
    }

    /// Removes every flow for which `keep` returns `false` and returns how
    /// many were removed (counted in [`ConntrackStats::removed`]).
    pub fn retain(&self, mut keep: impl FnMut(&Flow) -> bool) -> usize {
        let mut table = self.lock();
        let doomed: Vec<usize> = table
            .indices()
            .filter(|&index| table.entry(index).is_some_and(|entry| !keep(&entry.flow)))
            .collect();
        for &index in &doomed {
            self.remove_at(&mut table, index);
        }
        table.counters.removed += doomed.len() as u64;
        doomed.len()
    }

    /// Removes the flow a packet with `tuple` belongs to, in either
    /// direction, and returns it (counted in [`ConntrackStats::removed`]).
    /// O(1); an expired flow that is still in the table is removed and
    /// returned too.
    pub fn remove(&self, tuple: &FiveTuple) -> Option<Flow> {
        let mut table = self.lock();
        let (index, _) = table.find(tuple)?;
        let flow = self.remove_at(&mut table, index)?;
        table.counters.removed += 1;
        Some(flow)
    }

    /// Removes the entry at `index` and reports it to the removal hook.
    fn remove_at(&self, table: &mut Table, index: usize) -> Option<Flow> {
        let flow = table.remove(index)?.flow;
        if let Some(hook) = &self.on_remove {
            hook(&flow);
        }
        Some(flow)
    }

    /// Removes the expired flows among the next [`SWEEP_BATCH`] slots.
    fn sweep(&self, table: &mut Table, now: Instant) {
        for _ in 0..SWEEP_BATCH {
            let Some(index) = table.next_cursor() else {
                return;
            };
            if table
                .entry(index)
                .is_some_and(|entry| self.is_expired(entry, now))
            {
                self.remove_at(table, index);
                table.counters.expired += 1;
            }
        }
    }

    fn is_expired(&self, entry: &Entry, now: Instant) -> bool {
        now.saturating_duration_since(entry.last_seen) >= self.timeout(&entry.flow)
    }

    const fn timeout(&self, flow: &Flow) -> Duration {
        match (flow.original.protocol, flow.tcp_state) {
            (protocol::TCP, Some(TcpState::Established)) => self.config.tcp_established_timeout,
            (protocol::TCP, _) => self.config.tcp_transitory_timeout,
            (protocol::ICMP | protocol::ICMPV6, _) => self.config.icmp_timeout,
            _ => self.config.udp_timeout,
        }
    }

    fn lock(&self) -> MutexGuard<'_, Table> {
        self.table.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The tuple of a packet going the other way.
pub(crate) const fn reverse(tuple: &FiveTuple) -> FiveTuple {
    FiveTuple {
        src: tuple.dst,
        dst: tuple.src,
        protocol: tuple.protocol,
        src_port: tuple.dst_port,
        dst_port: tuple.src_port,
    }
}
